import os
import re
import subprocess
import sys
import click
import shutil
import requests
import xml.etree.ElementTree as ET  # Import ElementTree module
from zipfile import ZipFile

def print_title():
    print("""
    __  __  ____  ____         _____ _      _____ 
   |  \/  |/ __ \|  _ \       / ____| |    |_   _|
   | \  / | |  | | |_) |_____| |    | |      | |  
   | |\/| | |  | |  _ <______| |    | |      | |  
   | |  | | |__| | |_) |     | |____| |____ _| |_ 
   |_|  |_|\____/|____/       \_____|______|_____|
                                                  
    """)

def check_apksigner(input_apk):
    try:
        subprocess.check_output(["apksigner", "verify", input_apk], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print("\033[91mWARNING: This APK is not signed or the signature is not valid.\033[0m")
        print("\033[91mThis may indicate a security risk. Please ensure the APK is properly signed before distribution.\033[0m")
        print()  # Add a newline after the warning message
    except FileNotFoundError:
        print("\033[91mapksigner is not installed and is required for this script to function. It is part of the Android SDK Build Tools.")
        print("This tool assumes you have Android SDK Build Tools installed.")
        choice = input("Do you want to attempt to install apksigner? (Y/n): ").lower()
        if choice in ['y', 'yes']:
            print("Attempting to install apksigner using apt...")
            try:
                subprocess.run(["sudo", "apt", "update"])
                subprocess.run(["sudo", "apt", "install", "-y", "apksigner"])
                print("\033[92mapksigner has been installed successfully.\033[0m")
            except Exception as e:
                print("\033[91mError installing apksigner:", e, "\033[0m")
                print("\033[91mPlease install apksigner manually.\033[0m")
                sys.exit()
        else:
            print("\033[91mPlease install apksigner manually.\033[0m")
            sys.exit()


def check_aapt():
    try:
        subprocess.check_output(["aapt", "version"])
    except FileNotFoundError:
        print("\033[91maapt is not installed and is required for this script to function. It is part of the Android SDK Build Tools.")
        print("This tool assumes you have Android SDK Build Tools installed.")
        choice = input("Do you want to attempt to install aapt? (Y/n): ").lower()
        if choice in ['y', 'yes']:
            print("Attempting to install aapt using apt...")
            try:
                subprocess.run(["sudo", "apt", "update"])
                subprocess.run(["sudo", "apt", "install", "-y", "aapt"])
                print("\033[92maapt has been installed successfully.\033[0m")
            except Exception as e:
                print("\033[91mError installing aapt:", e, "\033[0m")
                print("\033[91mPlease install aapt manually.\033[0m")
                sys.exit()
        else:
            print("Please install aapt manually.")
            sys.exit()

def check_jadx():
    jadx_path = shutil.which("jadx")
    if jadx_path:
        return jadx_path
    else:
        print("\033[91mJADX is not found in your system.\033[0m")  # Print in red
        valid_choices = {"yes": True, "y": True, "no": False, "n": False}
        while True:
            choice = input("Do you want to download JADX now and temporarily set it in the environment path? (Y/n): ").lower()
            if choice in valid_choices:
                if valid_choices[choice]:
                    download_jadx()
                    return shutil.which("jadx")
                else:
                    print("\033[91mJADX is required for this tool to function. Exiting.\033[0m")  # Print in red
                    exit()
            else:
                print("Please respond with 'yes' or 'no' (or 'y' or 'n').")

def download_jadx():
    jadx_url = "https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip"
    jadx_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "jadx")
    jadx_executable_path = os.path.join(jadx_dir, "bin", "jadx")
    try:
        print("Downloading JADX...")
        with requests.get(jadx_url, stream=True) as response:
            with open("jadx.zip", "wb") as f:
                shutil.copyfileobj(response.raw, f)
        
        with ZipFile("jadx.zip", "r") as zip_ref:
            zip_ref.extractall(jadx_dir)
        
        os.remove("jadx.zip")
        
        os.chmod(jadx_executable_path, 0o755)  # Setting permission to make it executable
        
        print("\033[92mJADX has been downloaded successfully.\033[0m")
        
        # Add jadx directory to PATH
        os.environ['PATH'] += os.pathsep + os.path.join(jadx_dir, "bin")
        
        print("\033[92mJADX has been temporarily added to your environment path.\033[0m")
        
        return jadx_executable_path
    except Exception as e:
        print("\033[91mError downloading JADX:", e, "\033[0m")  # Print in red
        return None


def decompile_apk(input_apk, output_directory, jadx_path):
    try:
        print("Decompiling APK")
        # Perform decompilation using JADX
        process = subprocess.Popen([jadx_path, input_apk, "-d", output_directory], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while True:
            output = process.stdout.readline()
            if process.poll() is not None and output == b'':
                break
            if output:
                print(output.strip().decode("utf-8"))

        # Move decompiled files to the specified output directory
        decompiled_folder = os.path.join(output_directory, "sources")
        os.rename(os.path.join(output_directory, "sources"), decompiled_folder)
        
        print(f"Decompilation successful. Decompiled files saved in: {decompiled_folder}")
    except Exception as e:
        print(f"\033[91mError during decompilation: {e}\033[0m")  # Print in red

def analyze_apk(input_apk, output_file, output_dir):  # Add output_dir as an argument
    findings = []
    sdk_version = None  # Initialize sdk_version variable
    debuggable = False  # Initialize debuggable variable

    try:
        # Add analysis logic based on specified criteria
        findings.append("\nAnalysis findings for: " + input_apk)
        findings.append("")  # Add space
        findings.append("\033[1;94mAndroid Version Check:\033[0m")  # Make Android Version Check bold

        # Extract minSdkVersion and targetSdkVersion using aapt
        aapt_output = subprocess.check_output(["aapt", "dump", "badging", input_apk], text=True)
        min_sdk, target_sdk = extract_sdk_versions(aapt_output)

        check_and_append_target_sdk_version(findings, target_sdk)
        check_and_append_min_sdk_version(findings, min_sdk)

        print("\033[32m[*]\033[0m","Android Versions Extracted.")  # Print section completion
        
        # Check for APK signing schemes using apksigner        
        findings.append("")  # Add space
        findings.append("\033[1;94mAPK Signing Schemes:\033[0m")  # Make APK Signing Schemes bold

        apksigner_output = subprocess.check_output(["apksigner", "verify", "-verbose", input_apk], text=True)
        signing_schemes = extract_signing_schemes(apksigner_output)

        append_signing_schemes(findings, signing_schemes)

        print("\033[32m[*]\033[0m","APK Signing Schemes Extracted.")  # Print section completion

        # Check for vulnerable Janus exploit
        print("\033[32m[*]\033[0m","Checking for Janus Vulnerability...")  # Print section completion
        check_vulnerable_janus(findings, aapt_output, signing_schemes)

        # Extracted AndroidManifest.xml path
        manifest_path = os.path.join(output_dir, "resources", "AndroidManifest.xml")

        # Android Manifest Checks
        findings.append("")  # Add space
        findings.append("\033[1;94mAndroid Manifest Findings:\033[0m")
        debuggable = check_debuggable(findings, aapt_output)

        # Extract exported activities from AndroidManifest.xml
        exported_activities = extract_exported_activities(manifest_path)
        findings.append("\n Exported Activities:")
        for activity in exported_activities:
            findings.append(activity)

        print("\033[32m[*]\033[0m","Completed Android Manifest Checks")  # Print section completion

        # Write findings to the specified output file
        with open(output_file, 'w') as f:
            f.write('\n'.join(findings))

        # Print findings to the terminal
        for finding in findings:
            print(finding)

    except Exception as e:
        print(f"\033[91mError during analysis: {e}\033[0m")  # Print in red
        findings.append("Error during analysis: " + str(e))
        # Write findings to the specified output file in case of an error
        with open(output_file, 'w') as f:
            f.write('\n'.join(findings))
        
    print(f"\nAnalysis complete. Findings written to: {output_file}\n")  # Add spaces after printing

def extract_sdk_versions(aapt_output):
    min_sdk_match = re.search(r"sdkVersion:'(\d+)'", aapt_output)
    target_sdk_match = re.search(r"targetSdkVersion:'(\d+)'", aapt_output)
    min_sdk = int(min_sdk_match.group(1)) if min_sdk_match else None
    target_sdk = int(target_sdk_match.group(1)) if target_sdk_match else None
    return min_sdk, target_sdk

def check_and_append_min_sdk_version(findings, min_sdk):
    if min_sdk is not None:
        min_android_version = map_sdk_version_to_android_version(min_sdk)
        findings.append(f"Minimum SDK Version: {min_sdk} - {min_android_version}")
        if min_sdk <= 30:  # Android 11 or below
            version_warning = f"\033[91mWARNING: The app is compatible with Android version {min_sdk}, which is deprecated and not recommended for new development.\033[0m"
            findings.append(version_warning)
        elif min_sdk >= 31:  # Android 12 and above
            version_info = f"\033[32mINFO: This app is compatible with Android SDK versions {min_sdk} and up, which are all currently supported.\033[0m"
            findings.append(version_info)

def check_and_append_target_sdk_version(findings, target_sdk):
    if target_sdk is not None:
        target_android_version = map_sdk_version_to_android_version(target_sdk)
        findings.append(f"Target SDK Version: {target_sdk} - {target_android_version}")
        if target_sdk <= 30:  # Android 11 or below
            version_warning = f"\033[91mWARNING: The application is targeting Android version {target_sdk}, which is deprecated and not recommended for new development. Ensure that you have the latest APK.\033[0m"
            findings.append(version_warning)

def extract_signing_schemes(apksigner_output):
    signing_schemes = {"v1": False, "v2": False, "v3": False, "v4": False}
    verified_schemes = re.findall(r"Verified using v(\d) scheme \((.*?)\): (true|false)", apksigner_output)
    for match in verified_schemes:
        scheme = f"v{match[0]}"
        verified = match[2] == "true"
        signing_schemes[scheme] = verified
    return signing_schemes

def append_signing_schemes(findings, signing_schemes):
    for scheme, verified in signing_schemes.items():
        findings.append(f"{scheme}: {'Applied' if verified else 'Not Applied'}")

def check_vulnerable_janus(findings, aapt_output, signing_schemes):
    sdk_version_match = re.search(r"sdkVersion:'(\d+)'", aapt_output)
    if sdk_version_match:
        sdk_version = int(sdk_version_match.group(1))
        print(" \033[93m[*]\033[0m","Detected minSdkVersion:", sdk_version)
        if 21 <= sdk_version <= 26 and signing_schemes["v1"] and not any(signing_schemes[scheme] for scheme in ["v2", "v3", "v4"]):
            janus_warning = "\033[91mWARNING: The application may be vulnerable to the Janus exploit. It is signed with v1 only and targets Android versions 5.0 to 7.0.\033[0m"
            findings.append(janus_warning)
            print(" \033[93m[*]\033[0m","\033[91mPossibly vulnerable to Janus (CVE-2017–13156)\033[0m")
        elif 21 <= sdk_version <= 24 and signing_schemes["v1"] and any(signing_schemes[scheme] for scheme in ["v2", "v3", "v4"]):
            janus_warning = "\033[91mWARNING: The application may be vulnerable to the Janus exploit. It is signed with v1 and also v2, v3, or both schemes, and targets Android versions 5.0 to 7.0.\033[0m"
            findings.append(janus_warning)
            print(" \033[93m[*]\033[0m","\033[91mPossibly vulnerable to Janus (CVE-2017–13156)\033[0m")

def map_sdk_version_to_android_version(sdk_version):
    # Map SDK version to Android version
    android_versions = {
        21: "Android 5.0 (Lollipop)",
        22: "Android 5.1 (Lollipop)",
        23: "Android 6.0 (Marshmallow)",
        24: "Android 7.0 (Nougat)",
        25: "Android 7.1 (Nougat)",
        26: "Android 8.0 (Oreo)",
        27: "Android 8.1 (Oreo)",
        28: "Android 9.0 (Pie)",
        29: "Android 10 (Quince Tart)",
        30: "Android 11 (Red Velvet Cake)",
        31: "Android 12 (Snow Cone)",
        32: "Android 12.1 (Snow Cone v2)",
        33: "Android 13 (Tiramisu)",
        34: "Android 14 (Upside Down Cake)",
    }
    return android_versions.get(sdk_version, "Unknown Android Version")

def extract_android_manifest(input_apk):
    try:
        aapt_output = subprocess.check_output(["aapt", "dump", "xmltree", input_apk, "AndroidManifest.xml"], text=True)
        return aapt_output
    except Exception as e:
        print(f"\033[91mError extracting Android Manifest: {e}\033[0m")  # Print in red
        return None

def check_debuggable(findings, android_manifest):
    debuggable_match = re.search(r"android:debuggable=['\"](true)['\"]", android_manifest)
    if debuggable_match:
        debuggable_value = debuggable_match.group(1)
        if debuggable_value.lower() == 'true':
            findings.append("\033[91mWARNING: Debuggable set to true.\033[0m")
            return True
    findings.append("Debuggable set to false.")
    return False

def extract_exported_activities(manifest_path):
    exported_activities = []
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    # Iterate through all activity elements
    for activity in root.findall('.//activity'):
        activity_name = activity.get('{http://schemas.android.com/apk/res/android}name')
        exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
        
        # Check if the activity is exported
        if exported == 'true':
            exported_activities.append(activity_name)

    return exported_activities

@click.command()
@click.argument('input_apk', type=click.Path(exists=True, dir_okay=False))
@click.option('--output-dir', '-o', type=click.Path(), help='Specify output directory for decompiled files')
@click.option('--output-file', '-of', type=click.Path(), help='Specify output file for analysis findings')

def main(input_apk, output_dir, output_file):
    print_title()  # Print the title
    check_apksigner(input_apk)  # Check for apksigner availability
    check_aapt() # Check for aapt

    jadx_path = check_jadx()
    # Check if output directory is provided, otherwise use current working directory
    output_dir = output_dir or os.getcwd()

    # Check if output file is provided, otherwise use a default file
    output_file = output_file or 'analysis_findings.txt'

    # Perform decompilation
    decompile_apk(input_apk, output_dir, jadx_path)

    # Perform analysis
    analyze_apk(input_apk, output_file, output_dir)

if __name__ == '__main__':
    main()

