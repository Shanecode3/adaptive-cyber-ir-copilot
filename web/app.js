const phaseData = {
  1: {
    logs: `2025-01-01T12:00:01Z 10.0.0.5 POST /login 401 Mozilla/5.0
2025-01-01T12:00:02Z 10.0.0.5 POST /login 401 Mozilla/5.0
2025-01-01T12:00:03Z 10.0.0.5 POST /login 401 Mozilla/5.0
...
[WAF] ALERT LOGIN_BRUTE_FORCE MEDIUM rule=1001 path=/login`,
    behavior: `Behavior Label: SIMPLE_BRUTE_FORCE
MITRE: Credential Access (T1110)
Key Evidence:
- Single IP 10.0.0.5 with high volume of failed logins
- All requests against /login
- WAF brute-force alerts triggered`,
    summary: `Phase 1 Summary:
An attacker at 10.0.0.5 is performing a straightforward password brute-force attack against /login.
No sign of distribution or scanning yet.
Risk Level: MEDIUM
Top Suspicious IPs: 10.0.0.5
Main Targets: /login`,
    playbook: `Defense Plan:
1) RATE_LIMIT_IP 10.0.0.5 for 15 minutes
2) REQUIRE_CAPTCHA on /login for 1 hour
3) Increase logging on failed auth events
Strategy: Add friction to single-source brute-force without harming most users.`,
    critic: `Critic Assessment:
- Expected Outcome: Significant drop in failures from 10.0.0.5
- Likely Attacker Reaction: May rotate IPs or switch to credential stuffing in next phase
- FP Risk: LOW (rate limit is narrow and temporary)
Risk Score: 55/100 | Judgement: PARTIALLY_EFFECTIVE`,
  },
  2: {
    logs: `[Auth] Multiple IPs 10.0.1.10–10.0.1.40 failing logins across many users
[WAF] ALERT CREDENTIAL_STUFFING HIGH rule=2002 path=/login`,
    behavior: `Behavior Label: CREDENTIAL_STUFFING
MITRE: Credential Access (T1110.004)
Key Evidence:
- 20–30 IPs with low-volume failures each
- Many different user_ids targeted
- WAF detection of credential stuffing pattern`,
    summary: `Phase 2 Summary:
Attacker pivoted to distributed credential stuffing using likely leaked password lists.
Risk Level: HIGH
Top Suspicious IP Ranges: 10.0.1.0/24
Main Targets: /login
Affected Users: multiple accounts with repeated failed logins.`,
    playbook: `Defense Plan:
1) RATE_LIMIT_IP_RANGE 10.0.1.0/24 for 30 minutes
2) REQUIRE_CAPTCHA globally on /login for suspicious ASN/countries
3) Enable PASSWORD_RESET prompts for affected accounts
4) Tighten MFA enforcement for high-value users`,
    critic: `Critic Assessment:
- Attack Intensity Change vs Phase 1: -20% per-IP, +300% unique IPs
- Tactic Shift: YES (single-source brute-force -> distributed stuffing)
- Legitimate Impact: MEDIUM (more users see CAPTCHA)
Risk Score: 72/100 | Judgement: HIGH_RISK_BUT_CONTAINED`,
  },
  3: {
    logs: `[Web] 10.0.2.10 GET /admin 404
[Web] 10.0.2.10 GET /admin/login 302
[Web] 10.0.2.10 GET /api/users 401
[Web] 10.0.2.10 GET /api/config 403
[WAF] ALERT SCANNING MEDIUM rule=3003 path=/admin,/api/*`,
    behavior: `Behavior Label: APP_SCANNING
MITRE: Reconnaissance (TA0043)
Key Evidence:
- Targeted requests to /admin and /admin/login
- Probing /api/users and /api/config
- WAF flagging scanning / probing rules`,
    summary: `Phase 3 Summary:
Attacker appears to have shifted from credential attacks to application reconnaissance and endpoint discovery.
Risk Level: HIGH (if combined with previous credential access)
Main Targets: /admin, /api/users, /api/config`,
    playbook: `Defense Plan:
1) BLOCK_IP 10.0.2.10 for 60 minutes
2) Tighten WAF rules around /admin and /api/*
3) Enable extra logging + alerting for privileged endpoints
4) Consider canary endpoints to track future probes`,
    critic: `Critic Assessment:
- Attack Intensity: Lower request volume, but higher sensitivity endpoints
- Tactic Shift: YES (credential abuse -> recon/scanning)
- Legitimate Impact: LOW (admin-only endpoints)
Risk Score: 80/100 | Judgement: HIGH_RISK_TARGETED_RECON`,
  },
};

const logView = document.getElementById("logView");
const behaviorPanel = document.getElementById("behaviorPanel");
const summaryPanel = document.getElementById("summaryPanel");
const playbookPanel = document.getElementById("playbookPanel");
const criticPanel = document.getElementById("criticPanel");
const phaseButtons = document.querySelectorAll(".phase-btn");

function renderPhase(phase) {
  const data = phaseData[phase];
  if (!data) return;

  logView.textContent = data.logs;
  behaviorPanel.textContent = data.behavior;
  summaryPanel.textContent = data.summary;
  playbookPanel.textContent = data.playbook;
  criticPanel.textContent = data.critic;
}

phaseButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    phaseButtons.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const phase = btn.getAttribute("data-phase");
    renderPhase(phase);
  });
});

// initial phase
renderPhase(1);