# STIX-IAM-Report

## Overview

This repository contains a set of scripts and model classes to generate a STIX threat report which denotes IAM specific anomalies and signatures. 

## Usage

- First call the setup.py script which initially creates meta data about the report. 
- Afterward, call any script of the observe dictionary to generate an observation of anomalies or signatures. These scripts will also create corresponding vulnerabilities and course of actions and related objects.
- Finally, the finalize.py script will bundle the report to export it to systems which speak STIX.

## Example
Click on this [Link](https://oasis-open.github.io/cti-stix-visualization/?url=https://raw.githubusercontent.com/IAMmeetsCTI/IAM-meets-CTI/main/example.json) for visualizing the example.json (cancel the alert to show as list and wait a moment for the visualization to load).
