# MailSleuth

A lightweight, ethical email OSINT tool written in Python. MailTrace gathers **public data only** about an email address and its domain.

## Features

- Email syntax validation
- Domain DNS checks (MX, SPF, DMARC)
- Disposable email domain detection
- Public Gravatar profile check
- Data breach lookup via HaveIBeenPwned (optional, API key required)
- Text or JSON output

## Installation

```bash
git clone https://github.com/Blackbox-Wolfy/MailSleuth.git
cd MailSleuth
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python email_osint.py someone@example.com
python email_osint.py someone@example.com --json
```

### Enable breach lookup (optional)

Get an API key from [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key), then:

```bash
export HIBP_API_KEY="your-key-here"     # Windows (PowerShell): $env:HIBP_API_KEY="your-key-here"
python email_osint.py someone@example.com
```

## Ethical Use

Use MailSleuth **only** on email addresses you own or have explicit permission to investigate. Do not use it for harassment, stalking, or any unlawful activity. You are responsible for complying with local laws and the terms of any service queried.

## License

MIT License. See [LICENSE](LICENSE).
