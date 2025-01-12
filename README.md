# Mind the Gap: Uncovering Privacy Pitfalls in mHealth Apps

## Overview
This project provides an in-depth analysis of the privacy and security practices of 856 mHealth apps from the Google Play Store. The study covers 225 countries, 18 app categories, and includes paid, top-grossing, and CDC-endorsed apps. The research evaluates compliance with GDPR, HIPAA, COPPA, and Google’s privacy guidelines, focusing on discrepancies in data handling practices, security measures, and transparency in privacy policies.

The goal of this project is to identify key privacy issues, highlight inconsistencies in data handling, and provide a roadmap for improving security and privacy in the mHealth ecosystem.

## Research Questions

The study investigates the following research questions (RQs):
- **RQ1:** *Are the types of personal data collected and their purposes clearly defined?*
- **RQ2:** *Are the types of data shared with third parties specified, including their purposes and recipients?* 
- **RQ3:** *Are users informed about their rights to access, correct, or delete their data, as well as to opt out of marketing communications?*
- **RQ4:** *Is data encrypted during transmission?* 
- **RQ5:** *Are security measures described to prevent unauthorized access or data breaches?*
- **RQ6:** *Is contact information provided for addressing inquiries or complaints?* 
- **RQ7:** *Are children’s data and parental consent requirements explicitly addressed?* 
- **RQ8:** *Does the privacy policy disclosure for each app appear clear, vague, or entirely omitted?* 
- **RQ9:** *Are relevant privacy laws adequately explained?* 
- **RQ10:** *What factors influence the privacy compliance and security measures of mHealth apps?* 
- **RQ11:** *What are the key issues in mHealth apps, and what exemplary practices can app developers adopt?* 

## Methodology
The analysis uses both static and dynamic approaches:
- Static analysis: Examined the `Data Safety` section, privacy policies, and APK files for permissions and trackers.
- Dynamic analysis: Observed network traffic to assess the types of data transmitted and how they align with the privacy claims made by the apps.

We compared privacy claims from different sources to highlight discrepancies and non-compliance with privacy laws. This included:
- Google Play’s `Data Safety` section
- Privacy policies
- APK files (permissions and trackers)
- Network traffic

## Contributions
- Comprehensive analysis of 856 mHealth apps across 18 categories, providing insights into privacy and security challenges.
- Identification of vulnerabilities through static and dynamic analyses.
- Discrepancies in privacy claims: Highlighted inconsistencies between privacy policies, Data Safety disclosures, and observed data handling practices.
- Key findings: 
  - Free apps tend to offer more transparency, while paid apps excel in compliance.
  - Top-grossing apps lead in privacy and data sharing, while non-top-grossing apps focus on security and consistency.
  - CDC-endorsed apps showed discrepancies between their privacy policies and data safety disclosures.
- Ethical considerations: Ensured reproducibility of results without disclosing specific app information. The code is publicly available on [GitHub](https://github.com/hdoo7/mhealth_apps).

## Dataset
- Total apps analyzed: 856
- Categories analyzed: 18 (e.g., Health & Fitness, Medical, Parenting, Lifestyle, Education, Others)
- Average downloads per app: ~22.3 million
- Countries covered: 225
- Key sub-categories: 
  - 25 paid apps
  - 188 top-grossing apps
  - 2 CDC-endorsed apps

## Key Findings
- Data Specification: A significant portion of mHealth apps fail to specify the types of data they collect and share, which is a critical concern for user privacy.
- Security Measures: Encryption and security measures are often underreported, leaving users vulnerable to data breaches.
- Compliance with Regulations: Many apps do not fully comply with privacy laws like GDPR and HIPAA, even though they claim compliance in privacy policies.
- Transparency: Free apps generally have more transparent privacy practices compared to paid apps.

## Installation and Usage

To run the analysis using Jupyter Notebook, follow these steps:

### Step 1: Install Jupyter Notebook
#### On Windows:
1. Install Python: Download and install the latest version of Python from the official [Python website](https://www.python.org/downloads/). During installation, ensure that you check the box to "Add Python to PATH."
2. Install Jupyter Notebook: Open the Command Prompt and run the following command:
   ```bash
   pip install notebook
   ```

#### On macOS:
1. Install Python: If Python is not already installed, download and install the latest version of Python from the official [Python website](https://www.python.org/downloads/). Alternatively, you can use Homebrew to install it:
   ```bash
   brew install python
   ```
2. Install Jupyter Notebook: Open the Terminal and run the following command:
   ```bash
   pip install notebook
   ```

#### On Linux (Ubuntu/Debian):
1. Install Python: If Python is not already installed, run the following command to install it:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```
2. Install Jupyter Notebook: After installing Python, run the following command:
   ```bash
   pip3 install notebook
   ```

### Step 2: Clone the Repository
Clone this repository to your local machine using Git:
```bash
git clone https://github.com/hdoo7/mhealth_apps.git
```

### Step 3: Launch Jupyter Notebook
After installing Jupyter Notebook, you can launch it by running the following command in your terminal (or Command Prompt on Windows):
```bash
jupyter notebook
```

This will open Jupyter Notebook in your default web browser.

### Step 4: Run the Analysis
In Jupyter Notebook, navigate to the notebook file (e.g., `01_mhealth_apps.ipynb`) and run the cells to perform the analysis. You can execute a cell by selecting it and pressing `Shift + Enter`.


## Cite the code:
[![DOI](https://zenodo.org/badge/905789572.svg)](https://doi.org/10.5281/zenodo.14632265)

