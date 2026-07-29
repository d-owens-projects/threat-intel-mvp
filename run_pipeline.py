import subprocess
import sys

def run_step(description, command):
    print(f"\n=== {description} ===")
    result = subprocess.run(command, shell=True)

    if result.returncode != 0:
        print(f"❌ Step failed: {description}")
        sys.exit(1)
    else:
        print(f"✅ Step completed: {description}")

def main():
    print("\n🔥 Threat Intel MVP Pipeline Starting...\n")

    # Step 1: Normalize → STIX
    run_step("Normalizing raw indicators into STIX", "python normalize.py")

    # Step 2: Generate Sigma + YARA
    run_step("Generating Sigma + YARA detections", "python generate_detections.py")

    # Step 3: Generate AI Flash Report
    run_step("Generating AI-assisted flash report", "python model_workflow.py")

    print("\n🎉 Pipeline completed successfully!")
    print("Your STIX, Sigma, YARA, and Flash Report are ready.\n")

if __name__ == "__main__":
    main()
