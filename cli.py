import argparse
import json
from pathlib import Path
import pandas as pd
from phishing_detector import analyze_email, analyze_dataframe

def main():
    parser = argparse.ArgumentParser(description="Offline-first phishing email triage")
    parser.add_argument("--subject", default="")
    parser.add_argument("--sender", default="")
    parser.add_argument("--body", default="")
    parser.add_argument("--urls", default="")
    parser.add_argument("--attachments", default="")
    parser.add_argument("--display-url-text", default="")
    parser.add_argument("--csv", help="Input CSV for batch analysis")
    parser.add_argument("--output", help="Output CSV path for batch mode")
    parser.add_argument("--json", action="store_true", help="Print single-email result as JSON")
    args = parser.parse_args()

    if args.csv:
        df = pd.read_csv(args.csv).fillna("")
        if "body" not in df.columns:
            parser.error("CSV input must contain a 'body' column")
        result = analyze_dataframe(df)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            result.to_csv(args.output, index=False)
            print(f"Saved analysis to {args.output}")
        else:
            print(result.to_string(index=False))
        return

    result = analyze_email(args.subject, args.sender, args.body, args.urls, args.attachments, args.display_url_text)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f'Verdict: {result["verdict"]} ({result["score"]}/100)')
    print(f'Indicators: {result["finding_count"]}')
    for finding in result["findings"]:
        print(f'- [{finding["points"]} pts] {finding["indicator"]}: {finding["detail"]}')
    print(f'Recommendation: {result["recommendation"]}')

if __name__ == "__main__":
    main()
