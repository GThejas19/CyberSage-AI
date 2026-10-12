print("CyberSage test file is running!")

from analyzer import analyze_input


def main():
    test_inputs = [
        "URGENT ACTION: verify your account immediately "
        "at http://192.168.1.10/login",
        "https://example.com",
        "Your account has been suspended. Share your OTP immediately."
    ]

    for number, sample in enumerate(test_inputs, start=1):
        result = analyze_input(sample)

        print(f"\nCyberSage Analyzer Test #{number}")
        print("-" * 40)
        print("Input:", sample)
        print("Risk level:", result["risk"])
        print("Heuristic score:", result["score"])
        print("ML prediction:", result["prediction"])
        print("ML confidence:", result["confidence"])
        print("\nFindings:")

        for finding in result["findings"]:
            print("-", finding)


if __name__ == "__main__":
    main()