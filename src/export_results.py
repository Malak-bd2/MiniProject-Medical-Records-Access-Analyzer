
import csv

def export_results(results):

    with open("access_alerts.csv", "w", newline="", encoding="utf-8") as file:

        fieldnames = results[0].keys()

        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(results)

    print("Results exported successfully!")
