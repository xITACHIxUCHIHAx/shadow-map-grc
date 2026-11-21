from pathlib import Path
from urllib.parse import urljoin, urlparse
import json
import re

from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:5000"
MAX_PAGES = 60
OUTPUT_DIR = Path("ui_audit")
SCREENSHOT_DIR = OUTPUT_DIR / "screenshots"

OUTPUT_DIR.mkdir(exist_ok=True)
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

report = {
    "base_url": BASE_URL,
    "pages_checked": [],
    "issues": [],
    "browser_errors": [],
}


def normalize_url(url):
    parsed = urlparse(url)
    normalized_path = parsed.path or "/"
    return parsed._replace(path=normalized_path).geturl()


def safe_filename(url):
    path = urlparse(url).path.strip("/") or "home"
    name = re.sub(r"[^a-zA-Z0-9_-]+", "_", path)
    return name[:100]


def inspect_layout(page, url, viewport_name):
    return page.evaluate("""() => {
        const issues = [];
        const width = window.innerWidth;
        const height = window.innerHeight;
        const docWidth = document.documentElement.scrollWidth;

        function isVisible(el) {
            if (!el || !el.isConnected || !el.getClientRects().length) {
                return false;
            }

            for (
                let node = el;
                node && node.nodeType === Node.ELEMENT_NODE;
                node = node.parentElement
            ) {
                const style = window.getComputedStyle(node);

                if (
                    style.display === "none" ||
                    style.visibility === "hidden" ||
                    style.visibility === "collapse" ||
                    Number(style.opacity) === 0
                ) {
                    return false;
                }
            }

            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
        }

        function hasScrollableHorizontalAncestor(el) {
            for (
                let parent = el.parentElement;
                parent && parent !== document.body;
                parent = parent.parentElement
            ) {
                const style = window.getComputedStyle(parent);
                const overflowX = style.overflowX;

                if (
                    (overflowX === "auto" || overflowX === "scroll") &&
                    parent.scrollWidth > parent.clientWidth + 2
                ) {
                    return true;
                }
            }

            return false;
        }

        function hasAccessibleLabel(el) {
            if (el.labels && el.labels.length) {
                return true;
            }

            const ariaLabel = el.getAttribute("aria-label");
            if (ariaLabel && ariaLabel.trim()) {
                return true;
            }

            const labelledBy = el.getAttribute("aria-labelledby");

            if (labelledBy) {
                const ids = labelledBy.trim().split(/\\s+/);

                const text = ids.map(id => {
                    const node = document.getElementById(id);
                    return node ? node.textContent.trim() : "";
                }).join(" ").trim();

                if (text) {
                    return true;
                }
            }

            return false;
        }

        function isVisuallyHiddenControl(el) {
            const style = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect();

            if (
                Number(style.opacity) === 0 ||
                rect.width < 2 ||
                rect.height < 2
            ) {
                return true;
            }

            if (
                style.clip === "rect(0px, 0px, 0px, 0px)" ||
                style.clipPath === "inset(50%)"
            ) {
                return true;
            }

            return false;
        }

        if (docWidth > width + 2) {
            issues.push({
                type: "horizontal_overflow",
                viewport_width: width,
                document_width: docWidth
            });
        }

        document.querySelectorAll(
            'input, select, textarea, button'
        ).forEach((el) => {
            if (!isVisible(el)) {
                return;
            }

            const r = el.getBoundingClientRect();

            if (
                (r.left < -2 || r.right > width + 2) &&
                !hasScrollableHorizontalAncestor(el)
            ) {
                issues.push({
                    type: "control_outside_viewport",
                    tag: el.tagName,
                    control: el.type || "",
                    text: (el.innerText || el.value || "").trim().slice(0, 80),
                    left: Math.round(r.left),
                    right: Math.round(r.right),
                    viewport_width: width
                });
            }
        });

        document.querySelectorAll(
            'input[type="checkbox"], input[type="radio"]'
        ).forEach((el) => {
            if (!isVisible(el) || isVisuallyHiddenControl(el)) {
                return;
            }

            const label = el.labels && el.labels.length
                ? el.labels[0]
                : null;

            if (!label) {
                if (!hasAccessibleLabel(el)) {
                    issues.push({
                        type: "missing_control_label",
                        control: el.type,
                        name: el.name || "",
                        id: el.id || ""
                    });
                }
                return;
            }

            if (!isVisible(label)) {
                return;
            }

            const a = el.getBoundingClientRect();

            // Compare against the first rendered text line, not the
            // centre of a potentially multi-line label.
            const textRange = document.createRange();
            textRange.selectNodeContents(label);
            const textRects = [...textRange.getClientRects()].filter(
                rect => rect.width > 0 && rect.height > 0
            );

            const firstLine = textRects[0] || label.getBoundingClientRect();

            if (a.width && firstLine.width) {
                const centerA = a.top + a.height / 2;
                const centerB = firstLine.top + firstLine.height / 2;

                if (Math.abs(centerA - centerB) > 6) {
                    issues.push({
                        type: "checkbox_radio_alignment",
                        control: el.type,
                        label: label.innerText.trim().slice(0, 80),
                        vertical_difference: Math.round(
                            Math.abs(centerA - centerB)
                        )
                    });
                }
            }
        });

        const buttons = [...document.querySelectorAll(
            'button, input[type="submit"], a.btn, .button'
        )].filter(el => {
            if (!isVisible(el)) {
                return false;
            }

            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0;
        });

        // Compare equivalent controls only: same element, same classes,
        // and same table context. Table row actions often have deliberately
        // compact dimensions compared with page-level form actions.
        const buttonGroups = new Map();

        buttons.forEach(el => {
            const classes = [...el.classList].sort().join(".");
            const inTable = Boolean(el.closest("table"));
            const key = [
                el.tagName.toLowerCase(),
                classes,
                inTable ? "table" : "page"
            ].join("|");

            if (!buttonGroups.has(key)) {
                buttonGroups.set(key, []);
            }

            buttonGroups.get(key).push(el);
        });

        buttonGroups.forEach((group, groupName) => {
            if (group.length < 3) {
                return;
            }

            const heights = group.map(el =>
                Math.round(el.getBoundingClientRect().height)
            );

            const min = Math.min(...heights);
            const max = Math.max(...heights);

            if (max - min > 12) {
                issues.push({
                    type: "inconsistent_button_heights",
                    group: groupName,
                    count: group.length,
                    minimum: min,
                    maximum: max
                });
            }
        });

        return {
            viewport: {
                width,
                height,
                document_width: docWidth
            },
            issues
        };
    }""")



def discover_links(page, current_url):
    links = page.locator("a[href]").evaluate_all(
        "(els) => els.map(a => a.href)"
    )

    found = []

    for link in links:
        link = normalize_url(link)
        parsed = urlparse(link)
        base = urlparse(BASE_URL)

        if parsed.netloc != base.netloc:
            continue

        path = parsed.path.lower()

        if any(word in path for word in (
            "logout", "delete", "remove", "export", "download"
        )):
            continue

        if link not in found:
            found.append(link)

    return found


def inspect_page(browser, url):
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    errors = []

    page.on("pageerror", lambda error: errors.append(str(error)))

    page_result = {
        "url": url,
        "desktop": {},
        "narrow_desktop": {},
        "browser_errors": []
    }

    try:
        response = page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=30000
        )

        page.wait_for_timeout(1000)

        page_result["http_status"] = (
            response.status if response else None
        )
        page_result["final_url"] = page.url
        page_result["title"] = page.title()

        filename = safe_filename(url)

        page_result["desktop"] = inspect_layout(
            page, url, "desktop"
        )

        page.screenshot(
            path=str(SCREENSHOT_DIR / f"{filename}_desktop.png"),
            full_page=True
        )

        links = discover_links(page, url)

        page.set_viewport_size({
            "width": 1024,
            "height": 768
        })

        page.wait_for_timeout(500)

        page_result["narrow_desktop"] = inspect_layout(
            page, url, "narrow_desktop"
        )

        page.screenshot(
            path=str(SCREENSHOT_DIR / f"{filename}_narrow_desktop.png"),
            full_page=True
        )

        page_result["discovered_links"] = links
        page_result["browser_errors"] = errors

        for viewport in ("desktop", "narrow_desktop"):
            for issue in page_result[viewport].get("issues", []):
                report["issues"].append({
                    "url": url,
                    "viewport": viewport,
                    **issue
                })

        for error in errors:
            report["browser_errors"].append({
                "url": url,
                "error": error
            })

        return page_result, links

    except Exception as exc:
        page_result["error"] = str(exc)
        return page_result, []

    finally:
        page.close()


def main():
    visited = set()
    queue = [normalize_url(BASE_URL)]

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)

        while queue and len(visited) < MAX_PAGES:
            url = normalize_url(queue.pop(0))

            if url in visited:
                continue

            visited.add(url)
            print(f"[{len(visited)}/{MAX_PAGES}] Inspecting: {url}")

            page_result, links = inspect_page(browser, url)
            report["pages_checked"].append(page_result)

            for link in links:
                link = normalize_url(link)
                if link not in visited and link not in queue:
                    queue.append(link)

        browser.close()

    report["summary"] = {
        "total_pages": len(report["pages_checked"]),
        "total_issues": len(report["issues"]),
        "browser_errors": len(report["browser_errors"])
    }

    output_file = OUTPUT_DIR / "audit_report.json"
    output_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\nUI audit completed.")
    print(f"Pages inspected: {len(visited)}")
    print(f"Layout issues: {len(report['issues'])}")
    print(f"Browser errors: {len(report['browser_errors'])}")
    print(f"Report: {output_file}")
    print(f"Screenshots: {SCREENSHOT_DIR}")


if __name__ == "__main__":
    main()
