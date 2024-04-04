import os
import re
import subprocess
import sys
import click
import shutil
import requests
import xml.etree.ElementTree as ET
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
        print("\033[91m[*]\033[0m \033[91mWARNING:\033[0m This APK is not signed or the signature is not valid.")
        print("\033[91mThis may indicate a security risk. Please ensure the APK is properly signed before distribution.\033[0m")
        print()
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
        print("\033[91mJADX is not found in your system.\033[0m")
        valid_choices = {"yes": True, "y": True, "no": False, "n": False}
        while True:
            choice = input("Do you want to download JADX now and temporarily set it in the environment path? (Y/n): ").lower()
            if choice in valid_choices:
                if valid_choices[choice]:
                    download_jadx()
                    return shutil.which("jadx")
                else:
                    print("\033[91mJADX is required for this tool to function. Exiting.\033[0m")
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
        
        os.chmod(jadx_executable_path, 0o755)
        
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
        print(f"\033[91mError during decompilation: {e}\033[0m")

def analyze_apk(input_apk, output_file, output_dir):
    findings = []
    sdk_version = None
    debuggable = False

    try:
        findings.append("\nAnalysis findings for: " + input_apk)
        findings.append("")
        findings.append("\033[1;94mAndroid Version Check:\033[0m")

        aapt_output = subprocess.check_output(["aapt", "dump", "badging", input_apk], text=True)
        min_sdk, target_sdk = extract_sdk_versions(aapt_output)

        check_and_append_target_sdk_version(findings, target_sdk)
        check_and_append_min_sdk_version(findings, min_sdk)

        print("\033[32m[*]\033[0m","Android Versions Extracted.")
           
        findings.append("")
        findings.append("\033[1;94mAPK Signing Schemes:\033[0m")

        apksigner_output = subprocess.check_output(["apksigner", "verify", "-verbose", input_apk], text=True)
        signing_schemes = extract_signing_schemes(apksigner_output)

        append_signing_schemes(findings, signing_schemes)

        print("\033[32m[*]\033[0m","APK Signing Schemes Extracted.")

        print("\033[32m[*]\033[0m","Checking for Janus Vulnerability...")
        check_vulnerable_janus(findings, aapt_output, signing_schemes)

        manifest_path = os.path.join(output_dir, "resources", "AndroidManifest.xml")

        findings.append("")
        findings.append("\033[1;94mAndroid Manifest Findings:\033[0m")
        findings.append("\033[93m\n  General:\033[0m")
        debuggable = check_debuggable(findings, aapt_output)
        check_backup_settings(findings, manifest_path, debuggable)
        check_network_security(findings, manifest_path, output_dir)

        exported_activities = extract_exported_activities(manifest_path)
        findings.append("\033[93m\n Exported Activities:\033[0m")
        for activity in exported_activities:
            findings.append(activity)

        manifest_path = os.path.join(output_dir, "resources", "AndroidManifest.xml")
        findings.append("\033[93m\n Content Providers:\033[0m")

        content_provider_findings = analyze_content_providers(manifest_path)
        findings.extend(content_provider_findings)

        print("\033[32m[*]\033[0m Content Providers Extracted.")

        # Write findings to file
        with open(output_file, 'w') as f:
            f.write('\n'.join(findings))

        manifest_path = os.path.join(output_dir, "resources", "AndroidManifest.xml")
        br_and_url_findings = analyze_broadcast_receivers_and_url_schemes(manifest_path)
        findings.extend(br_and_url_findings)

        print("\033[32m[*]\033[0m","Completed Android Manifest Checks")

        with open(output_file, 'w') as f:
            f.write('\n'.join(findings))

        for finding in findings:
            print(finding)

        service_findings = analyze_exported_services(manifest_path)
        findings.extend(service_findings)

    except Exception as e:
        print(f"\033[91mError during analysis: {e}\033[0m")
        findings.append("Error during analysis: " + str(e))
        with open(output_file, 'w') as f:
            f.write('\n'.join(findings))
        
    print(f"\nAnalysis complete. Findings written to: {output_file}\n")

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
            version_warning = f"\033[91m[*]\033[0m \033[91mWARNING:\033[0m The app is compatible with Android version {min_sdk}, which is deprecated and not recommended for new development."
            findings.append(version_warning)
        elif min_sdk >= 31:  # Android 12 and above
            version_info = f"\033[32mINFO: This app is compatible with Android SDK versions {min_sdk} and up, which are all currently supported.\033[0m"
            findings.append(version_info)

def check_and_append_target_sdk_version(findings, target_sdk):
    if target_sdk is not None:
        target_android_version = map_sdk_version_to_android_version(target_sdk)
        findings.append(f"Target SDK Version: {target_sdk} - {target_android_version}")
        if target_sdk <= 30:
            version_warning = f"\033[91m[*]\033[0m \033[91mWARNING:\033[0m The application is targeting Android version {target_sdk}, which is deprecated and not recommended for new development. Ensure that you have the latest APK."
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
            janus_warning = "\033[91m[*]\033[0m \033[91mWARNING:\033[0m The application may be vulnerable to the Janus exploit. It is signed with v1 only and targets Android versions 5.0 to 7.0."
            findings.append(janus_warning)
            print(" \033[93m[*]\033[0m","Possibly vulnerable to Janus (CVE-2017–13156)")
        elif 21 <= sdk_version <= 24 and signing_schemes["v1"] and any(signing_schemes[scheme] for scheme in ["v2", "v3", "v4"]):
            janus_warning = "\033[91m[*]\033[0m \033[91mWARNING:\033[0m The application may be vulnerable to the Janus exploit. It is signed with v1 and also v2, v3, or both schemes, and targets Android versions 5.0 to 7.0.\033"
            findings.append(janus_warning)
            print(" \033[93m[*]\033[0m","Possibly vulnerable to Janus (CVE-2017–13156)")

def map_sdk_version_to_android_version(sdk_version):
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
        print(f"\033[91mError extracting Android Manifest: {e}\033[0m")
        return None

def check_debuggable(findings, android_manifest):
    debuggable_match = re.search(r"android:debuggable=['\"](true)['\"]", android_manifest)
    if debuggable_match:
        debuggable_value = debuggable_match.group(1)
        if debuggable_value.lower() == 'true':
            findings.append("\033[91m[*]Debuggable set to true.\033[0m")
            return True
    findings.append("\033[32m[*]\033[0m Debuggable set to false.")
    return False

def check_backup_settings(findings, manifest_path, debuggable):
    try:
        with open(manifest_path, 'r') as manifest_file:
            manifest_content = manifest_file.read()

        if 'android:allowBackup="false"' in manifest_content:
            findings.append("\033[32m[*]\033[0m android:allowBackup=\"false\" attribute is explicitly set.")
        else:
            findings.append("\033[93m[*]\033[0m android:allowBackup=\"false\" attribute is not explicitly set. Consider setting it to prevent unauthorised data backups.")
        
        if 'android:allowBackup="true"' in manifest_content and debuggable:
            findings.append("\033[91m[*]\033[0m \033[91mWARNING:\033[0m Backup Settings: Both android:allowBackup=\"true\" and android:debuggable=\"true\" are present. This configuration may pose security risks as it allows unauthorised data backups via adb when usb debugging is enabled.")
            
    except Exception as e:
        findings.append("\033[91mERROR:\033[0m Error occurred while checking backup settings.")
        print(f"\033[91mError checking backup settings: {e}\033[0m")

def check_network_security(findings, manifest_path, output_dir):
    try:
        with open(manifest_path, 'r') as manifest_file:
            manifest_content = manifest_file.read()
            findings.append("\nNetwork Security:")

        if 'android:networkSecurityConfig="@xml/network_security_config"' in manifest_content:
            findings.append("Custom network security configurations found.")
            network_security_config_path = os.path.join(output_dir, "resources", "res", "xml", "network_security_config.xml")
            if os.path.isfile(network_security_config_path):
                findings.append("Custom network security configuration file found: network_security_config.xml")
                
                tree = ET.parse(network_security_config_path)
                root = tree.getroot()
                
                # Global cleartextTrafficPermitted setting under <base-config>
                base_config = root.find(".//base-config")
                if base_config is not None:
                    global_cleartext = base_config.get('cleartextTrafficPermitted')
                    if global_cleartext == "true":
                        findings.append("\033[91m[*]\033[0m \033[91mWARNING:\033[0m Global cleartext traffic is permitted (base-config).")
                
                # Check each <domain-config> for cleartextTrafficPermitted
                for domain_config in root.findall(".//domain-config"):
                    domain_cleartext = domain_config.get('cleartextTrafficPermitted')
                    domain_names = [domain.text for domain in domain_config.findall(".//domain")]
                    domain_names_str = ", ".join(domain_names) if domain_names else "Unknown"
                    if domain_cleartext == "true":
                        findings.append(f"\033[91m[*]\033[0m \033[91mWARNING:\033[0m Cleartext traffic permitted for domain(s): {domain_names_str} (domain-config).")
                    
            else:
                findings.append("\033[91mERROR:\033[0m Custom network security configuration file 'network_security_config.xml' is missing.")
        else:
            findings.append("Network Security: No custom network security configurations found in AndroidManifest.xml.")

    except Exception as e:
        findings.append("\033[91mERROR:\033[0m Error occurred while checking network security configurations.")
        print(f"\033[91mError checking network security configurations: {e}\033[0m")

def extract_exported_activities(manifest_path):
    exported_activities = []
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    for activity in root.findall('.//activity'):
        activity_name = activity.get('{http://schemas.android.com/apk/res/android}name')
        exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
        
        if exported == 'true':
            exported_activities.append(activity_name)

    return exported_activities

def extract_content_providers(manifest_path):
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    namespace = '{http://schemas.android.com/apk/res/android}'

    providers = []
    file_provider_note = "Note: Review the FileProvider's XML configuration for secure paths."

    for provider in root.findall(".//provider"):
        name = provider.attrib.get(f'{namespace}name', 'Unknown')
        authorities = provider.attrib.get(f'{namespace}authorities', 'None specified')
        exported = provider.attrib.get(f'{namespace}exported', 'false')
        is_file_provider = "androidx.core.content.FileProvider" in name or "android.support.v4.content.FileProvider" in name

        provider_info = {
            "name": name,
            "authorities": authorities,
            "exported": exported == 'true',
            "is_file_provider": is_file_provider,
            "note": file_provider_note if is_file_provider else ""
        }
        providers.append(provider_info)

    return providers

def analyze_content_providers(manifest_path):
    findings = []
    namespace = '{http://schemas.android.com/apk/res/android}'
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    findings.append("\nContent Providers:")
    providers = root.findall(".//provider")
    for provider in providers:
        name = provider.attrib.get(f'{namespace}name')
        authorities = provider.attrib.get(f'{namespace}authorities')
        exported = provider.attrib.get(f'{namespace}exported', 'false')
        permission = provider.attrib.get(f'{namespace}permission', None)  # Ensure permission is defined
        grantUriPermissions = provider.attrib.get(f'{namespace}grantUriPermissions', 'false')
        is_file_provider = "FileProvider" in name or "android.support.v4.content.FileProvider" in name
        
        export_status = "Exported" if exported == "true" else "Not Exported"
        findings.append(f"  {export_status} Content Provider: {name}")
        findings.append(f"    - Authorities: {authorities}")
        if permission:  # Check if permission variable is not None
            findings.append(f"    - Protected by permission: {permission}")
        if is_file_provider:
            findings.append("    - Type: FileProvider")
            findings.append("      Note: Review the FileProvider's XML configuration for secure paths.")
        if grantUriPermissions == "true":
            findings.append("    - Grant URI permissions: Yes")

    return findings


def analyze_broadcast_receivers_and_url_schemes(manifest_path):
    findings = []
    namespace = "{http://schemas.android.com/apk/res/android}"
    standard_schemes = {"http", "https"}

    tree = ET.parse(manifest_path)
    root = tree.getroot()

    # Broadcast Receivers Analysis
    findings.append("\nBroadcast Receivers Analysis:")
    receivers = root.findall(".//receiver")
    for receiver in receivers:
        receiver_name = receiver.attrib.get(f"{namespace}name")
        exported = receiver.attrib.get(f"{namespace}exported", "false")
        permission = receiver.attrib.get(f"{namespace}permission")
        
        export_status = "Exported" if exported == "true" else "Not Exported"
        findings.append(f"  {export_status} Broadcast Receiver found: {receiver_name}")
        if permission:
            findings.append(f"    - Requires permission: {permission}")

        # Intent filter actions and categories
        intent_filters = receiver.findall(".//intent-filter")
        for intent_filter in intent_filters:
            actions = intent_filter.findall(".//action")
            for action in actions:
                action_name = action.attrib.get(f"{namespace}name", "None")
                findings.append(f"    - Responds to action: {action_name}")
            categories = intent_filter.findall(".//category")
            for category in categories:
                category_name = category.attrib.get(f"{namespace}name", "None")
                findings.append(f"    - In category: {category_name}")

    # URL Schemes Analysis
    findings.append("\nURL Schemes Analysis:")
    activities = root.findall(".//activity")
    for activity in activities:
        activity_name = activity.attrib.get(f"{namespace}name")
        intent_filters = activity.findall(".//intent-filter")
        for intent_filter in intent_filters:
            data_elements = intent_filter.findall(".//data")
            if not data_elements:
                findings.append(f"    - Activity {activity_name} has an intent filter without specific data, which could be overly broad.")
            for data_element in data_elements:
                scheme = data_element.attrib.get(f"{namespace}scheme")
                if scheme:
                    if scheme in standard_schemes:
                        findings.append(f"    - Activity {activity_name} handles standard URL scheme: {scheme}")
                    else:
                        findings.append(f"    - Activity {activity_name} handles custom URL scheme: {scheme}")

    return findings

    return findings

def analyze_exported_services(manifest_path):
    findings = []
    namespace = '{http://schemas.android.com/apk/res/android}'

    tree = ET.parse(manifest_path)
    root = tree.getroot()
    services = root.findall(".//service")

    for service in services:
        name = service.get(f'{namespace}name')
        exported = service.get(f'{namespace}exported', 'false')
        permission = service.get(f'{namespace}permission')

        if exported == 'true':
            findings.append(f"WARNING: Exported Service found: {name}")
            if permission:
                findings.append(f"    - Protected by permission: {permission}")
            else:
                findings.append(f"    - No permission required, potentially insecure.")

    return findings

@click.command()
@click.argument('input_apk', type=click.Path(exists=True, dir_okay=False))
@click.option('--output-dir', '-o', type=click.Path(), help='Specify output directory for decompiled files')
@click.option('--output-file', '-of', type=click.Path(), help='Specify output file for analysis findings')

def main(input_apk, output_dir, output_file):
    print_title()
    check_apksigner(input_apk)
    check_aapt()
    jadx_path = check_jadx()
    output_dir = output_dir or os.getcwd()
    output_file = output_file or 'analysis_findings.txt'
    decompile_apk(input_apk, output_dir, jadx_path)
    analyze_apk(input_apk, output_file, output_dir)

if __name__ == '__main__':
    main()

