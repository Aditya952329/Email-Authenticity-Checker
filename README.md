# Email Authenticity Checker

A Python-based tool to verify the authenticity of received emails using:

- SPF validation
- DMARC record check
- DKIM detection
- Domain age analysis
- Authentication-Results header parsing

## How to Run

Activate virtual environment:

    .venv\Scripts\activate

Install dependencies:

    pip install -r requirements.txt

Run:

    python auth_mail_checker.py