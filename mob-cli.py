import os
import re
import subprocess
import click
from distutils.spawn import find_executable  # Add this line
import shutil
import sys

def check_apksigner():
    # Check if apksigner is available
    if shutil.which("apksigner") is None:
        print("apksigner is not installed. It is part of the Android SDK Build Tools.")
        print("Please make sure you have the Android SDK Build Tools installed.")
        print("Would you like instructions on how to install Android SDK Build Tools now? (y/n)")
        choice = input().strip().lower()
        if choice == "y":
            # Provide instructions on how to install Android SDK Build Tools manually
            print("To install Android SDK Build Tools, please follow these steps:")
            print("1. Download and install Android Studio from https://developer.android.com/studio")
            print("2. Once installed, open Android Studio and go to Tools > SDK Manager.")
            print("3. In the SDK Manager, select 'Android SDK Build-Tools' under the 'SDK Tools' tab.")
            print("4. Click 'Apply' to install the selected packages.")
            print("5. Make sure the 'sdkmanager' and 'apksigner' tools are added to your system PATH.")
            sys.exit()
        else:
            print("apksigner is required for this script to function. Please install Android SDK Build Tools manually.")
            sys.exit()

# Call the function to check for apksigner
check_apksigner()

def check_jadx():
    jadx_path = find_executable("jadx")
    if jadx_path:
        return jadx_path
    else:
        print("\033[91mJADX is not found in your system.\033[0m")  # Print in red
        valid_choices = {"yes": True, "y": True, "no": False, "n": False}
        while True:
            choice = input("Do you want to download JADX now? (Y/n): ").lower()
            if choice in valid_choices:
                if valid_choices[choice]:
                    download_jadx()
                    return find_executable("jadx")
                else:
                    print("\033[91mJADX is required for this tool to function. Exiting.\033[0m")  # Print in red
                    exit()
            else:
                print("Please respond with 'yes' or 'no' (or 'y' or 'n').")

def download_jadx():
    jadx_url = "https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip"
    try:
        with closing(urlopen(jadx_url)) as jadx_zip:
            with ZipFile(io.BytesIO(jadx_zip.read())) as zfile:
                zfile.extractall(os.path.join(str(Path(__file__).parent), "jadx"))
        jadx_executable_path = find_executable("jadx")
        os.chmod(jadx_executable_path, 0o755)  # Setting permission to make it executable
        print("\033[92mJADX has been downloaded and installed successfully.\033[0m")  # Print in green
    except Exception as e:
        print("\033[91mError downloading JADX: {e}\033[0m")  # Print in red
        exit()

def decompile_apk(input_apk, output_directory, jadx_path):
    try:
        # Perform decompilation using JADX
        subprocess.run([jadx_path, input_apk, "-d", output_directory], check=True)
        
        # Move decompiled files to the specified output directory
        decompiled_folder = os.path.join(output_directory, "sources")
        os.rename(os.path.join(output_directory, "sources"), decompiled_folder)
        
        print(f"Decompilation successful. Decompiled files saved in: {decompiled_folder}")
    except Exception as e:
        print(f"\033[91mError during decompilation: {e}\033[0m")  # Print in red

def analyze_apk(input_apk, output_file):
    findings = []

    try:
        # Add analysis logic based on specified criteria
        findings.append("Analysis findings for: " + input_apk)
        
        # Check for APK signing schemes using apksigner
        apksigner_output = subprocess.check_output(["apksigner", "verify", "-verbose", input_apk], text=True)

        # Extract APK signing schemes and their verification status
        signing_schemes = {"v1": False, "v2": False, "v3": False, "v4": False}
        verified_schemes = re.findall(r"Verified using v(\d) scheme \((.*?)\): (true|false)", apksigner_output)
        for match in verified_schemes:
            scheme = f"v{match[0]}"
            verified = match[2] == "true"
            signing_schemes[scheme] = verified

        # Print the APK signing schemes and their verification status
        findings.append("APK signing schemes:")
        for scheme, verified in signing_schemes.items():
            findings.append(f"{scheme}: {'Verified' if verified else 'Not Verified'}")
            if verified:
                print(f"{scheme}: {'Verified'}")
            else:
                print(f"{scheme}: {'Not Verified'}")

        # Check for missing v3 or v4 schemes
        if not signing_schemes["v3"] or not signing_schemes["v4"]:
            missing_warning = "\033[93mWARNING: Modern signing schemes (v3, v4) are not fully applied. Consider applying them for enhanced security.\033[0m"
            findings.append(missing_warning)
            print(missing_warning)

        # Check for deprecated Android SDK versions
        android_versions = subprocess.check_output(["aapt", "dump", "badging", input_apk], text=True)
        sdk_version_match = re.search(r"sdkVersion:'(\d+)'", android_versions)
        if sdk_version_match:
            sdk_version = int(sdk_version_match.group(1))
            if sdk_version <= 29:  # Android 10 or below
                warning = f"\033[91mWARNING: The app is compatible with Android SDK version {sdk_version}, which is deprecated.\033[0m"
                findings.append(warning)
                print(warning)
            elif sdk_version == 30:  # Android 11
                warning = f"\033[91mWARNING: Android 11 (API level 30) is now end of life and not recommended for new development.\033[0m"
                findings.append(warning)
                print(warning)

        # Add more analysis criteria based on your requirements

        # Write findings to the specified output file
        with open(output_file, 'w') as f:
            f.write('\n'.join(findings))
        
        print(f"Analysis complete. Findings written to: {output_file}")
    except Exception as e:
        print(f"\033[91mError during analysis: {e}\033[0m")  # Print in red


@click.command()
@click.argument('input_apk', type=click.Path(exists=True, dir_okay=False))
@click.option('--output-dir', '-o', type=click.Path(), help='Specify output directory for decompiled files')
@click.option('--output-file', '-of', type=click.Path(), help='Specify output file for analysis findings')
def main(input_apk, output_dir, output_file):
    jadx_path = check_jadx()
    # Check if output directory is provided, otherwise use current working directory
    output_dir = output_dir or os.getcwd()

    # Check if output file is provided, otherwise use a default file
    output_file = output_file or 'analysis_findings.txt'

    # Perform decompilation
    decompile_apk(input_apk, output_dir, jadx_path)

    # Perform analysis and write findings to the specified file
    analyze_apk(input_apk, output_file)

if __name__ == '__main__':
    main()

