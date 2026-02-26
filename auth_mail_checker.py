#!/usr/bin/env python3

import dns.resolver
import whois
import re
from email import message_from_string
from email.policy import default
from datetime import datetime


class EmailAuthenticityChecker:

    def __init__(self, raw_email):
        self.msg = message_from_string(raw_email, policy=default)
        self.results = {}
        self.score = 0

    # Extract sender domain
    def extract_sender_domain(self):
        from_header = self.msg.get("From")
        if not from_header:
            return None

        match = re.search(r'@([\w.-]+)', from_header)
        if match:
            return match.group(1)
        return None

    # Check Authentication-Results header (Important)
    def check_authentication_results(self):
        auth_header = self.msg.get("Authentication-Results")

        if not auth_header:
            self.results["Authentication-Results"] = "Not Present"
            return

        self.results["Authentication-Results"] = auth_header

        if "spf=pass" in auth_header.lower():
            self.score += 1

        if "dkim=pass" in auth_header.lower():
            self.score += 1

        if "dmarc=pass" in auth_header.lower():
            self.score += 1

    # SPF DNS Record Check
    def check_spf_record(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for record in answers:
                for txt_string in record.strings:
                    if b'v=spf1' in txt_string:
                        self.results["SPF Record"] = "Present"
                        return
            self.results["SPF Record"] = "Not Found"
        except:
            self.results["SPF Record"] = "Lookup Failed"

    # DMARC DNS Record Check
    def check_dmarc_record(self, domain):
        try:
            dmarc_domain = "_dmarc." + domain
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for record in answers:
                for txt_string in record.strings:
                    if b'v=DMARC1' in txt_string:
                        self.results["DMARC Record"] = "Present"
                        return
            self.results["DMARC Record"] = "Not Found"
        except:
            self.results["DMARC Record"] = "Lookup Failed"

    # Domain Age Check
    def check_domain_age(self, domain):
        try:
            w = whois.query(domain)
            creation_date = w.creation_date
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                self.results["Domain Age (days)"] = age_days
                if age_days > 180:
                    self.score += 1
            else:
                self.results["Domain Age"] = "Unknown"
        except:
            self.results["Domain Age"] = "Lookup Failed"

    # Generate Report
    def generate_report(self):
        print("\n========== Email Authenticity Report ==========")
        for key, value in self.results.items():
            print(f"{key}: {value}")

        print("\nAuthenticity Score:", self.score, "/ 4")

        if self.score >= 3:
            print("Final Verdict: Likely Legitimate")
        elif self.score == 2:
            print("Final Verdict: Suspicious - Needs Manual Review")
        else:
            print("Final Verdict: High Risk / Possibly Spoofed")


def main():
    print("Paste the FULL raw email below.")
    print("Type END on a new line when finished.\n")

    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)

    raw_email = "\n".join(lines)

    checker = EmailAuthenticityChecker(raw_email)
    domain = checker.extract_sender_domain()

    if not domain:
        print("Could not extract sender domain.")
        return

    print(f"\nChecking sender domain: {domain}")

    checker.check_authentication_results()
    checker.check_spf_record(domain)
    checker.check_dmarc_record(domain)
    checker.check_domain_age(domain)
    checker.generate_report()


if __name__ == "__main__":
    main()