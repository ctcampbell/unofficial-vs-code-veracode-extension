# Unofficial Veracode Extension

## Features

* Scan an app with Veracode Pipeline Scan.
* Load results from Veracode Pipeline Scan.
* Load results from Veracode SCA.

## Usage

* Right click on a zip, war, jar, or ear to scan.
* Right click on a `*.json` file to load a set of scan results.

### SCA results file creation

Mac/Linux:

    srcclr scan --json [--no-upload] > veracode-sca-results.json

Windows (Powershell 6+):

    srcclr scan --json [--no-upload] | out-file veracode-sca-results.json -encoding utf8NoBOM

## Configuration

The following settings are available:

    "unofficialVeracodeExtension.authProfile": {
        "type": "string",
        "default": "default",
        "description": "Veracode authentication profile section from ~/.veracode/credentials"
    },
    "unofficialVeracodeExtension.pipelineScanResultsFilename": {
        "type": "string",
        "default": "veracode-pipeline-scan-results.json",
        "description": "Veracode Pipeline Scan results file name"
    },
    "unofficialVeracodeExtension.scaResultsFilename": {
        "type": "string",
        "default": "veracode-sca-results.json",
        "description": "Veracode SCA Scan results file name"
    },
    "unofficialVeracodeExtension.sourceRoot": {
        "type": "string",
        "default": "",
        "description": "Source code root folder"
    },
    "unofficialVeracodeExtension.jspRoot": {
        "type": "string",
        "default": "",
        "description": "JSP root folder"
    }

`unofficialVeracodeExtension.sourceRoot` and `unofficialVeracodeExtension.jspRoot` can be used to prefix filenames in the scan results where the Veracode engine does not have full visibilty of the source code directory structure (e.g. Java scan results will be scoped to the `com/example/app/` directory and this usually requires prefixing with `src/main/java` or similar to create a system filepath). These settings are not typically needed for languages scanned as source code, so long as the zip archive created for a scan contains the full folder structure of the source code (usually this means you should zip the `src/` folder or similar).
