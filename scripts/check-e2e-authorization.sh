#!/usr/bin/env bash
# check-e2e-authorization.sh — Decide whether a PR may run e2e tests in CI.
#
# Authorized when the PR author is a trusted bot (e.g. renovate-fullsend[bot]),
# when the collaborator permission API confirms write+ access (admin, maintain,
# write), or when this run is an ok-to-test labeled event from a user with
# write+ access.
#
# Do not base trust on author_association: GitHub reports MEMBER or COLLABORATOR
# for users with read or triage roles, which must not run credentialed CI.
# Trust is based strictly on the collaborator permission API (write, maintain, admin).
#
# A retained ok-to-test label does not approve opened, synchronize, reopened,
# or any other event. On those events a label that does not postdate the
# frozen PR updated_at (PR_UPDATED_AT) is removed. A label applied after that
# timestamp is left for the labeled workflow and does not authorize this run
# (reason=fresh_ok_to_test). Does not use committer.date (author-controlled).
#
# Usage: check-e2e-authorization.sh PR_NUMBER OWNER/REPO
#
# Environment (optional, from workflow):
#   PR_AUTHOR_ASSOCIATION — github.event.pull_request.author_association
#   PR_AUTHOR_LOGIN — github.event.pull_request.user.login
#   PR_UPDATED_AT — github.event.pull_request.updated_at
#   EVENT_ACTION  — github.event.action
#   LABEL_ACTOR_LOGIN — github.event.sender.login (who applied the label on
#     labeled events)
#
# Writes authorized, reason, and label_removed to GITHUB_OUTPUT when set.
# Exits 0 always; callers inspect outputs.

set -euo pipefail

PR_NUMBER="${1:?PR number required}"
REPOSITORY="${2:?repository (owner/repo) required}"

TRUSTED_BOT_LOGINS="renovate-fullsend[bot] fullsend-ai-coder[bot]"
OK_TO_TEST_LABEL="ok-to-test"

write_error_output() {
  echo "check-e2e-authorization: API or script error (see log above)" >&2
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      echo "authorized=false"
      echo "reason=error"
      echo "label_removed=false"
    } >>"${GITHUB_OUTPUT}"
  fi
  printf 'authorized=false reason=error label_removed=false\n'
}

trap 'write_error_output; exit 0' ERR

is_trusted_bot() {
  local login="${1:-}"
  case " ${TRUSTED_BOT_LOGINS} " in
    *" ${login} "*) return 0 ;;
    *) return 1 ;;
  esac
}

# Check actor has write+ permission via the collaborator permission API.
# Base trust strictly on write+ permissions (admin, maintain, write), never
# on author_association which can include triage/read members.
# API errors (network, 500, rate limits) route to the ERR trap rather than
# silently denying or deleting labels.
get_collaborator_role() {
  local username="${1:-}"
  local api_err perm_json role
  if [[ -z "${username}" ]]; then
    echo "none"
    return 0
  fi
  api_err="$(mktemp)"
  if ! perm_json="$(gh api "repos/${REPOSITORY}/collaborators/${username}/permission" 2>"${api_err}")"; then
    if grep -qiE "not a collaborator|404|not found" "${api_err}"; then
      rm -f "${api_err}"
      echo "none"
      return 0
    fi
    cat "${api_err}" >&2
    rm -f "${api_err}"
    return 1
  fi
  rm -f "${api_err}"
  role="$(jq -r '.role_name // "none"' <<<"${perm_json}")"
  echo "${role}"
}

is_write_role() {
  case "${1:-}" in
    admin|maintain|write) return 0 ;;
    *) return 1 ;;
  esac
}

# The ERR trap is not inherited by functions: return 1 so it fires at the call.
remove_ok_to_test_label() {
  if [[ "${CHECK_E2E_AUTH_DRY_RUN:-}" != "true" ]]; then
    gh api -X DELETE "repos/${REPOSITORY}/issues/${PR_NUMBER}/labels/${OK_TO_TEST_LABEL}" >/dev/null || return 1
  fi
  label_removed=true
}

label_removed=false
authorized=false
reason="unauthorized"

# Ensure PR_AUTHOR_LOGIN is populated if not provided via environment.
if [[ -z "${PR_AUTHOR_LOGIN:-}" ]]; then
  pr_json="$(gh api "repos/${REPOSITORY}/pulls/${PR_NUMBER}")"
  PR_AUTHOR_LOGIN="$(jq -r '.user.login // ""' <<<"${pr_json}")"
fi

if is_trusted_bot "${PR_AUTHOR_LOGIN:-}"; then
  authorized=true
  reason="trusted_bot"
else
  if ! author_role="$(get_collaborator_role "${PR_AUTHOR_LOGIN:-}")"; then
    write_error_output
    exit 0
  fi
  if is_write_role "${author_role}"; then
    authorized=true
    reason="trusted_author"
  else
    pr_json="${pr_json:-$(gh api "repos/${REPOSITORY}/pulls/${PR_NUMBER}")}"
    has_ok_label="$(jq -r --arg label "${OK_TO_TEST_LABEL}" '[.labels[].name] | index($label) != null' <<<"${pr_json}")"

    if [[ "${has_ok_label}" == "true" ]]; then
      if [[ "${EVENT_ACTION:-}" == "labeled" ]]; then
        authorized=true
        reason="ok_to_test"
      else
        # Only the labeled event approves a run. An older label is stale.
        # A label applied after this event belongs to the labeled workflow.
        events_json="$(gh api "repos/${REPOSITORY}/issues/${PR_NUMBER}/events" --paginate | jq -s 'add // []')"
        ok_to_test_at="$(jq -r --arg label "${OK_TO_TEST_LABEL}" '
          [.[] | select(.event == "labeled" and (.label.name // "") == $label) | .created_at] | max // empty
        ' <<<"${events_json}")"

        last_push_at="${PR_UPDATED_AT:-}"
        if [[ -z "${last_push_at}" ]]; then
          # Fallback: live updated_at is noisy (bumped by comments, labels, etc.)
          # and may over-reject. Prefer the frozen event-payload value (PR_UPDATED_AT).
          last_push_at="$(jq -r '.updated_at // empty' <<<"${pr_json}")"
        fi

        if [[ -n "${ok_to_test_at}" && -n "${last_push_at}" && "${ok_to_test_at}" > "${last_push_at}" ]]; then
          reason="fresh_ok_to_test"
        else
          remove_ok_to_test_label
          reason="stale_ok_to_test"
        fi
      fi
    fi
  fi
fi

# A label is an authorization boundary: the user who last applied ok-to-test
# must currently have write+ permission. Triage-role users can apply labels
# without it, so the label alone does not prove a maintainer approved the run.
latest_labeler() {
  if [[ -z "${events_json:-}" ]]; then
    events_json="$(gh api "repos/${REPOSITORY}/issues/${PR_NUMBER}/events" --paginate | jq -s 'add // []')" || return 1
  fi
  jq -r --arg label "${OK_TO_TEST_LABEL}" '
    [.[] | select(.event == "labeled" and (.label.name // "") == $label)]
    | max_by(.created_at // "") | .actor.login // empty
  ' <<<"${events_json}"
}

if [[ "${reason}" == "ok_to_test" ]]; then
  # On labeled events the frozen payload names the labeler of this run. A
  # later re-label by someone else must not authorize this run's head.
  frozen_labeler=""
  if [[ "${EVENT_ACTION:-}" == "labeled" ]]; then
    frozen_labeler="${LABEL_ACTOR_LOGIN:-}"
  fi
  labeler_login="${frozen_labeler}"
  if [[ -z "${labeler_login}" ]]; then
    labeler_login="$(latest_labeler)"
  fi

  # Any missing identity results in denial (Fail Closed).
  if [[ -z "${labeler_login}" ]]; then
    authorized=false
    reason="untrusted_labeler"
    remove_ok_to_test_label
  else
    if ! labeler_role="$(get_collaborator_role "${labeler_login}")"; then
      write_error_output
      exit 0
    fi

    # Remove the label so a maintainer's re-apply fires a new labeled event.
    # Keep it when someone else has re-applied it since: that run decides.
    if ! is_write_role "${labeler_role}"; then
      authorized=false
      reason="untrusted_labeler"
      if [[ -z "${frozen_labeler}" || "$(latest_labeler)" == "${frozen_labeler}" ]]; then
        remove_ok_to_test_label
      fi
    fi
  fi
fi

trap - ERR

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "authorized=${authorized}"
    echo "reason=${reason}"
    echo "label_removed=${label_removed}"
  } >>"${GITHUB_OUTPUT}"
fi

printf 'authorized=%s reason=%s label_removed=%s\n' "${authorized}" "${reason}" "${label_removed}"
