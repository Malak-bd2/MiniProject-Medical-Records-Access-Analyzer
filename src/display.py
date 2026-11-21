from datetime import datetime, timedelta


def display_alerts(results):

    print("\nMEDICAL RECORDS ACCESS ANALYZER")
    print("=" * 60)
    print("\nSUSPICIOUS ACCESS DETECTED")
    print("=" * 60)

    # Group logs by user and date
    user_logs = {}

    for row in results:
        key = (row["user_name"], row["access_time"][:10])
        user_logs.setdefault(key, []).append(row)

    # Group suspicious logs by user
    suspicious_users = {}

    for row in results:
        if row["alert_level"] != "Normal":
            suspicious_users.setdefault(
                row["user_name"], []
            ).append(row)

    if not suspicious_users:
        print("\nNo suspicious access detected.")

    for user, suspicious_rows in suspicious_users.items():

        print(f"\nDoctor: {user}")
        print("-" * 60)

        displayed_volume_windows = set()

        for row in suspicious_rows:

            reasons = row["reasons"].split(", ")

            for reason in reasons:

                if reason == "Outside working hours":
                    print("\nViolation: Outside working hours")
                    print("Severity: Low")
                    print(f"File: {row['record_id']}")
                    print(f"Time: {row['access_time']}")

                elif reason == "Outside user's department":
                    print("\nViolation: Outside user's department")
                    print("Severity: Medium")
                    print(f"File: {row['record_id']}")
                    print(
                        f"Record Department: "
                        f"{row['record_department']}"
                    )
                    print(f"Time: {row['access_time']}")

                elif reason == "Unusual access volume":

                    date = row["access_time"][:10]
                    key = (user, date)

                    day_logs = user_logs[key]

                    parsed_times = [
                        datetime.strptime(
                            r["access_time"], "%Y-%m-%d %H:%M"
                        )
                        for r in day_logs
                    ]

                    first_time = min(parsed_times)

                    access_time = datetime.strptime(
                        row["access_time"], "%Y-%m-%d %H:%M"
                    )

                    window_number = int(
                        (access_time - first_time).total_seconds() // 3600
                    )

                    window_key = (user, date, window_number)

                    if window_key not in displayed_volume_windows:

                        displayed_volume_windows.add(window_key)

                        window_start = first_time + timedelta(
                            hours=window_number
                        )

                        window_end = window_start + timedelta(hours=1)

                        window_logs = [
                            r for r in day_logs
                            if window_start <= datetime.strptime(
                                r["access_time"], "%Y-%m-%d %H:%M"
                            ) < window_end
                        ]

                        files = sorted({
                            r["record_id"] for r in window_logs
                        })

                        print("\nViolation: Unusual access volume")
                        print("Severity: High")
                        print(f"Number of files: {len(files)}")
                        print(
                            f"Time Window: "
                            f"{window_start.strftime('%H:%M')} - "
                            f"{window_end.strftime('%H:%M')}"
                        )
                        print(f"Files: {', '.join(files)}")

        print("\n" + "-" * 60)
