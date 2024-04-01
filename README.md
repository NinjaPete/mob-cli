# mob-cli

mob-cli is a Python script that decompiles and analyses Android APK files. It checks various aspects of the APK for common security misconfigurations.

## Features

- **APK Analysis**: Analyse Android APK files for compatibility, signing schemes, and vulnerabilities.
- **APK Decompilation**: Decompile APK files to examine their internal code and resources.
- **More to come**

## Requirements

- Python 3.x
- JDK (for JADX)
- Android SDK Build Tools (for aapt and apksigner)

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/your_username/apk-analyzer.git
   ```
2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```
3. Ensure that jadx, apksigner, and aapt are installed. If they are not, the script will attempt to install them for you.

## Usage
Run the script against an APK file:
```
python mob-cli.py <target-apk>.apk
```

Opional arguments:
`--output-dir` or `-o` Specify the output directory
`--output-file` or `-of` Specify the output file for analysis findings

Example:

```
python mob-cli.py <target-apk>.apk -o /path/to/directory -of analysis_results.txt
```
## License

This project is licensed under the MIT License.


