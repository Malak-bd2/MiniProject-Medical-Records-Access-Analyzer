# MiniProject-Medical-Records-Access-Analyzer

A Python-based tool for analyzing medical records access logs and detecting potentially suspicious activities using predefined security rules.

## 1. Project Overview

The **Medical Records Access Analyzer** is a Python-based mini-project developed as part of the **Security and Privacy** module.

The project aims to analyze access logs and identify potentially suspicious activities related to medical records. It examines user access patterns and detects activities that may violate predefined access rules.

## 2. Project Objectives

The main objectives are:

- Analyze medical records access logs.
- Identify access activities occurring outside normal working hours.
- Detect unusually high access volumes.
- Identify access to records outside a user's assigned department.
- Assign suspicion scores and classify detected activities according to their alert levels.
- Export and display the analysis results.

## 3. Detection Mechanisms

The system examines access logs using the following detection rules:

| Detection rule | Description | Suspicion score |
|---|---|---:|
| Access outside working hours | Detects access outside the 08:00–20:00 period. | 2 |
| Unusual access volume | Detects access to more than 10 distinct records within a one-hour window. | 7 |
| Department violation | Detects access to records outside the user's department. | 3 |

The system classifies the resulting suspicion scores into three alert levels:

- **Normal:** Score less than or equal to 2.
- **Medium Alert:** Score greater than 2 and less than or equal to 3.
- **High Alert:** Score greater than 3.

## 4. Technologies and Requirements

- **Programming language:** Python 3.
- **Standard libraries identified:** `csv` and `datetime`.
- **Project modules:** `display` and `export_results`.

No external Python packages have been identified in the imports reviewed so far. The `requirements.txt` file is therefore currently empty, pending verification of all source files.

## 5. Project Structure

```text
MiniProject-Medical-Records-Access-Analyzer/
│
├── src/
│   ├── main.py
│   ├── display.py
│   └── export_results.py
│
├── data/
│   ├── access_logs.csv
│   └── access_alerts.csv
│
├── README.md
└── requirements.txt
```

### Main Components

- **main.py:** Reads the access logs, applies the detection rules, calculates suspicion scores, and calls the supporting modules.
- **display.py:** Displays suspicious access alerts and their associated details.
- **export_results.py:** Handles exporting the analysis results.
- **access_logs.csv:** Input file containing the access log records.
- **access_alerts.csv:** CSV file intended for the alert results.

## 6. Installation and Execution

### Prerequisites

- Python 3 installed on the computer.
- The project repository downloaded or cloned from GitHub.

### Running the Program

Open a terminal in the project directory, then navigate to the `data` folder:

```bash
cd data
```

Run the main Python program:

```bash
python ../src/main.py
```

This execution command assumes that the input CSV file is located in the `data` directory and that the program uses relative file paths as currently implemented.

## 7. Input and Output

**Input:**

- `access_logs.csv`: Contains the access records analyzed by the program.

**Output:**

- The program displays detected suspicious activities and their details.
- The analysis results are exported through the `export_results` module.

## 8. Limitations

The analysis depends on the quality and completeness of the provided access log data and the predefined detection rules. The system identifies suspicious patterns based on these rules; its alerts should not automatically be considered proof of unauthorized activity.
## 9. Authors

This project was developed by:

- GUENFOUD MALAK
- BENCHIKH MERIEM
- SAHRAOUI AMANI FATIMA ZOHRA
- RAHMEN DINA
- LAZREG IMANE
- OUETOUET ABIR

**Module:** Security and Privacy

**Academic Year:** 2026–2027

**Institution:** University of Sétif 1
