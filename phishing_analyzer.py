"""
Phishing Awareness Analysis
Project 3 - Cyber Security Industrial Training Kit
Author: Lohitaksh Raj
Batch: 2026
"""

import re
from urllib.parse import urlparse


class PhishingAnalyzer:
    """Analyzes emails/messages to detect phishing attempts."""

    # Common phishing keywords (urgency, threats, rewards)
    SUSPICIOUS_KEYWORDS = [
        "urgent", "verify your account", "suspended", "click here",
        "act now", "limited time", "congratulations", "you have won",
        "lottery", "prize", "claim now", "update your password",
        "confirm your identity", "unusual activity", "security alert",
        "wire transfer", "bitcoin", "gift card", "refund", "tax refund",
        "your account will be closed", "immediate action required",
        "dear customer", "dear user", "final notice", "free",
        "risk-free", "100% guaranteed", "bank details", "ssn",
        "social security", "otp", "one time password", "kyc"
    ]

    # Domains commonly used in phishing or URL shorteners
    SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".zip"]
    URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]

    # Legitimate-looking brands often impersonated
    IMPERSONATED_BRANDS = ["paypal", "amazon", "microsoft", "apple", "google",
                           "netflix", "facebook", "instagram", "sbi", "hdfc", "icici"]

    def __init__(self, message: str, sender: str = "unknown@unknown.com"):
        self.message = message
        self.sender = sender.lower()
        self.red_flags = []
        self.suspicious_links = []
        self.found_keywords = []
        self.score = 0

    # ---------- Detection Methods ----------

    def check_keywords(self):
        """Find phishing keywords in the message."""
        text = self.message.lower()
        for word in self.SUSPICIOUS_KEYWORDS:
            if word in text:
                self.found_keywords.append(word)
                self.score += 1
        if self.found_keywords:
            self.red_flags.append(
                f"Contains {len(self.found_keywords)} suspicious keyword(s): {', '.join(self.found_keywords)}"
            )

    def extract_links(self):
        """Extract all URLs from the message."""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        return re.findall(url_pattern, self.message)

    def check_links(self):
        """Analyze each URL for phishing indicators."""
        links = self.extract_links()
        for link in links:
            reasons = []
            parsed = urlparse(link if link.startswith("http") else "http://" + link)
            domain = parsed.netloc.lower()

            # Check URL shorteners
            for short in self.URL_SHORTENERS:
                if short in domain:
                    reasons.append(f"Uses URL shortener ({short}) to hide real destination")
                    self.score += 2

            # Check suspicious TLDs
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    reasons.append(f"Suspicious top-level domain ({tld})")
                    self.score += 2

            # IP address instead of domain name
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
                reasons.append("Uses raw IP address instead of domain name")
                self.score += 3

            # Brand impersonation in subdomain trick (e.g. paypal.secure-login.com)
            for brand in self.IMPERSONATED_BRANDS:
                if brand in domain and not domain.endswith(brand + ".com"):
                    reasons.append(f"Impersonates '{brand}' but is not the official domain")
                    self.score += 3

            # "@" symbol trick in URL
            if "@" in link:
                reasons.append("Contains '@' symbol — hides the real destination")
                self.score += 3

            # Too many dots / subdomains
            if domain.count(".") >= 3:
                reasons.append("Excessive subdomains (possible deception)")
                self.score += 1

            if reasons:
                self.suspicious_links.append({"url": link, "reasons": reasons})

        if self.suspicious_links:
            self.red_flags.append(f"Found {len(self.suspicious_links)} suspicious link(s)")

    def check_sender(self):
        """Check the sender's email address."""
        if "@" not in self.sender:
            return
        domain = self.sender.split("@")[-1]

        # Free email used as if from a company
        free_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
        for brand in self.IMPERSONATED_BRANDS:
            if brand in self.sender.split("@")[0] and domain in free_providers:
                self.red_flags.append(
                    f"Sender claims to be '{brand}' but uses a free email ({domain})"
                )
                self.score += 3

        # Lookalike domains (e.g. paypa1.com, amaz0n.com)
        if re.search(r"[0-9]", domain.split(".")[0]) and any(b in domain for b in self.IMPERSONATED_BRANDS):
            self.red_flags.append(f"Sender domain looks like a lookalike: {domain}")
            self.score += 2

    def check_grammar_and_tone(self):
        """Detect urgency, threats, and poor grammar."""
        text = self.message.lower()

        if "!!!" in self.message or self.message.count("!") >= 3:
            self.red_flags.append("Excessive exclamation marks — emotional manipulation")
            self.score += 1

        if re.search(r"\b(within \d+ hours?|in 24 hours|immediately|right now)\b", text):
            self.red_flags.append("Creates false urgency (time pressure tactic)")
            self.score += 2

        if re.search(r"dear (customer|user|sir/madam)", text):
            self.red_flags.append("Generic greeting instead of your real name")
            self.score += 1

        # Lots of uppercase = shouting
        uppercase_words = re.findall(r"\b[A-Z]{4,}\b", self.message)
        if len(uppercase_words) >= 3:
            self.red_flags.append("Excessive uppercase text (shouting / pressure)")
            self.score += 1

    # ---------- Main Runner ----------

    def analyze(self):
        self.check_keywords()
        self.check_links()
        self.check_sender()
        self.check_grammar_and_tone()
        return self.generate_report()

    def get_risk_level(self):
        if self.score >= 8:
            return "🔴 HIGH RISK — Almost certainly phishing"
        elif self.score >= 4:
            return "🟠 MEDIUM RISK — Likely phishing, do NOT click"
        elif self.score >= 1:
            return "🟡 LOW RISK — Some suspicious indicators, stay cautious"
        else:
            return "🟢 SAFE — No obvious phishing indicators found"

    def generate_report(self):
        report = []
        report.append("=" * 65)
        report.append("       PHISHING AWARENESS ANALYSIS REPORT")
        report.append("       Lohitaksh Raj  |  Project 3  |  Batch 2026")
        report.append("=" * 65)
        report.append(f"Sender    : {self.sender}")
        report.append(f"Risk Score: {self.score}")
        report.append(f"Verdict   : {self.get_risk_level()}")
        report.append("-" * 65)

        report.append("\n[1] RED FLAGS FOUND:")
        if self.red_flags:
            for i, flag in enumerate(self.red_flags, 1):
                report.append(f"   {i}. {flag}")
        else:
            report.append("   None")

        report.append("\n[2] SUSPICIOUS KEYWORDS DETECTED:")
        if self.found_keywords:
            report.append(f"   {', '.join(self.found_keywords)}")
        else:
            report.append("   None")

        report.append("\n[3] SUSPICIOUS LINKS:")
        if self.suspicious_links:
            for link in self.suspicious_links:
                report.append(f"   • {link['url']}")
                for reason in link["reasons"]:
                    report.append(f"       - {reason}")
        else:
            report.append("   None")

        report.append("\n[4] WHY THIS MESSAGE IS UNSAFE:")
        if self.score > 0:
            report.append("   This message uses social engineering tactics designed")
            report.append("   to trick the reader into clicking malicious links or")
            report.append("   revealing personal information. Indicators above show")
            report.append("   classic phishing behavior: urgency, impersonation,")
            report.append("   suspicious URLs, and emotional pressure.")
        else:
            report.append("   No unsafe indicators detected in this message.")
        report.append("=" * 65 + "\n")
        return "\n".join(report)


# ---------- Run Analysis on Sample Emails ----------

if __name__ == "__main__":
    from sample_emails import SAMPLES

    print("\n🛡  LOHITAKSH RAJ — PHISHING AWARENESS ANALYZER\n")
    for idx, sample in enumerate(SAMPLES, 1):
        print(f"\n########## EMAIL SAMPLE {idx} ##########")
        analyzer = PhishingAnalyzer(sample["body"], sample["from"])
        print(analyzer.analyze())
