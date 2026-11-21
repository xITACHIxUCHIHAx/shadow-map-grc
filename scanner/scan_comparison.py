"""Conservative comparison of observations from two Nmap scans."""

def service_label(port):
    parts = [
        port.get("service"),
        port.get("product"),
        port.get("version"),
    ]
    return " ".join(str(value).strip() for value in parts if value).strip() or "Unknown"


def compare_ports(baseline_ports, current_ports):
    """Compare by protocol and port; never infer closure from a missing row."""
    def indexed(rows):
        result = {}
        for row in rows:
            item = dict(row)
            key = (str(item.get("protocol") or "").lower(),
                   int(item["port"]))
            result[key] = item
        return result

    baseline = indexed(baseline_ports)
    current = indexed(current_ports)
    results = []

    for protocol, port_number in sorted(set(baseline) | set(current)):
        old = baseline.get((protocol, port_number))
        new = current.get((protocol, port_number))

        old_state = old.get("state", "Not reported") if old else "Not reported"
        new_state = new.get("state", "Not reported") if new else "Not reported"
        old_service = service_label(old) if old else "Not reported"
        new_service = service_label(new) if new else "Not reported"

        if old is None:
            change = "Not reported in baseline"
        elif new is None:
            change = "Not reported in current"
        else:
            state_changed = old_state.lower() != new_state.lower()
            service_changed = (
                service_label(old).lower() != service_label(new).lower()
            )
            if state_changed and service_changed:
                change = "State and service changed"
            elif state_changed:
                if old_state.lower() != "open" and new_state.lower() == "open":
                    change = "Port opened"
                elif old_state.lower() == "open" and new_state.lower() != "open":
                    change = "Port state changed from open"
                else:
                    change = "State changed"
            elif service_changed:
                change = "Service changed"
            else:
                change = "No change"

        results.append({
            "protocol": protocol,
            "port": port_number,
            "baseline_state": old_state,
            "current_state": new_state,
            "baseline_service": old_service,
            "current_service": new_service,
            "change_type": change,
        })

    return results
