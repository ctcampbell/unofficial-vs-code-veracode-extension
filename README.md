# Veracode Pipeline Scan

## Features

* Scan an app with Veracode Pipeline Scan.
* Load results from a Veracode Pipeline Scan.

## Usage

* Right click on a zip, war, jar, or ear to scan.
* Right click on a `*.json` file to load a set of scan results.

## Configuration

The following settings are available:

    "unofficialVeracodePipelineScan.resultsFileName": {
        "type": "string",
        "default": "unofficial-veracode-pipeline-scan-results.json",
        "description": "Scan results file name"
    },
    "unofficialVeracodePipelineScan.sourceRoot": {
        "type": "string",
        "default": "",
        "description": "Source code root folder"
    },
    "unofficialVeracodePipelineScan.jspRoot": {
        "type": "string",
        "default": "",
        "description": "JSP root folder"
    },
    "unofficialVeracodePipelineScan.authProfile": {
        "type": "string",
        "default": "default",
        "description": "Veracode authentication profile section from ~/.veracode/credentials"
    }

`unofficialVeracodePipelineScan.sourceRoot` and `unofficialVeracodePipelineScan.jspRoot` can be used to prefix filenames in the scan results where the Veracode engine does not have full visibilty of the source code directory structure (e.g. Java scan results will be scoped to the `com/example/app/` directory and this usually requires prefixing with `src/main/java` or similar to create a system filepath). These settings are not typically needed for languages scanned as source code, so long as the zip archive created for a scan contains the full folder structure of the source code (usually this means you should zip the `src/` folder or similar).
