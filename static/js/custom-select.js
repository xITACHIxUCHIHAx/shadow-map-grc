(() => {
  "use strict";

  const SELECTOR = [
    ".page-content select",
    "#global-ping-interval",
    "#global-ping-count"
  ].join(",");

  let instanceCounter = 0;

  function initSelect(select) {
    if (
      select.dataset.customSelectReady === "true" ||
      select.multiple ||
      select.size > 1
    ) return;

    const originalStyle = window.getComputedStyle(select);
    const originalRect = select.getBoundingClientRect();

    select.dataset.customSelectReady = "true";
    instanceCounter += 1;

    const wrapper = document.createElement("div");
    wrapper.className = "sm-select";

    const needsExtraWidth = select.matches(
      [
        "#global-ping-interval",
        "#global-ping-count",
        "#bulk-likelihood",
        "#bulk-impact",
        '.finding-form select[name="likelihood"]',
        '.finding-form select[name="impact"]'
      ].join(",")
    );

    const wrapperWidth = originalRect.width + (needsExtraWidth ? 48 : 0);

    Object.assign(wrapper.style, {
      display: originalStyle.display,
      width: `${wrapperWidth}px`,
      minWidth: originalStyle.minWidth,
      maxWidth: originalStyle.maxWidth,
      margin: originalStyle.margin,
      flex: originalStyle.flex,
      gridColumn: originalStyle.gridColumn,
      gridRow: originalStyle.gridRow,
      alignSelf: originalStyle.alignSelf,
      justifySelf: originalStyle.justifySelf,
      verticalAlign: originalStyle.verticalAlign
    });

    select.parentNode.insertBefore(wrapper, select);
    wrapper.appendChild(select);

    select.classList.add("sm-select-native");
    select.tabIndex = -1;
    select.setAttribute("aria-hidden", "true");

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "sm-select-trigger";

    Object.assign(trigger.style, {
      boxSizing: "border-box",
      width: "100%",
      height: `${originalRect.height}px`,
      minHeight: originalStyle.minHeight,
      maxHeight: originalStyle.maxHeight,
      padding: originalStyle.padding,
      paddingRight: `${(parseFloat(originalStyle.paddingRight) || 0) + 20}px`,
      fontFamily: originalStyle.fontFamily,
      fontSize: originalStyle.fontSize,
      fontWeight: originalStyle.fontWeight,
      lineHeight: originalStyle.lineHeight,
      letterSpacing: originalStyle.letterSpacing,
      textAlign: originalStyle.textAlign,
      textTransform: originalStyle.textTransform
    });

    trigger.setAttribute("role", "combobox");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");

    const label =
      select.getAttribute("aria-label") ||
      (select.labels && select.labels.length
        ? select.labels[0].textContent.trim()
        : "") ||
      select.name ||
      "Choose an option";

    trigger.setAttribute("aria-label", label);
    trigger.id = `sm-select-trigger-${instanceCounter}`;

    if (select.labels) {
      Array.from(select.labels).forEach(labelElement => {
        if (labelElement.control !== select) return;

        if (labelElement.htmlFor === select.id) {
          labelElement.htmlFor = trigger.id;
          return;
        }

        if (labelElement.contains(wrapper)) {
          labelElement.addEventListener("click", event => {
            const clickedTrigger =
              event.target instanceof Element &&
              event.target.closest(".sm-select-trigger");

            if (clickedTrigger) return;

            event.preventDefault();
            trigger.focus();
          });
        }
      });
    }

    const valueText = document.createElement("span");
    valueText.className = "sm-select-value";

    const arrow = document.createElement("span");
    arrow.className = "sm-select-arrow";
    arrow.setAttribute("aria-hidden", "true");

    trigger.append(valueText, arrow);

    const menu = document.createElement("div");
    menu.className = "sm-select-menu";
    menu.id = `sm-select-menu-${instanceCounter}`;
    menu.setAttribute("role", "listbox");
    menu.setAttribute("aria-label", label);
    menu.setAttribute("aria-hidden", "true");

    trigger.setAttribute("aria-controls", menu.id);

    wrapper.append(trigger, menu);

    let activeIndex = -1;
    let typeahead = "";
    let typeaheadTimer = null;
    let optionNodes = [];

    function getOptions() {
      return Array.from(select.options);
    }

    function selectedIndex() {
      return Math.max(0, select.selectedIndex);
    }

    function syncValue() {
      const option = select.options[select.selectedIndex];
      valueText.textContent = option ? option.textContent.trim() : "Select an option";
      trigger.disabled = select.disabled;

      if (select.disabled) {
        closeMenu();
      }
    }

    function enabledIndices() {
      return getOptions()
        .map((option, index) => ({ option, index }))
        .filter(({ option }) => {
          const group = option.parentElement;
          return !option.disabled && !(group && group.disabled);
        })
        .map(({ index }) => index);
    }

    function renderOptions() {
      menu.replaceChildren();
      optionNodes = [];

      const options = getOptions();

      options.forEach((option, index) => {
        const group = option.parentElement;
        const groupLabel =
          group && group.tagName === "OPTGROUP" ? group.label : "";

        if (
          groupLabel &&
          (index === 0 || options[index - 1].parentElement !== group)
        ) {
          const heading = document.createElement("div");
          heading.className = "sm-select-group";
          heading.textContent = groupLabel;
          menu.appendChild(heading);
        }

        const item = document.createElement("div");
        item.className = "sm-select-option";
        item.id = `${menu.id}-option-${index}`;
        item.setAttribute("role", "option");
        item.dataset.index = String(index);
        item.textContent = option.textContent.trim();
        item.setAttribute(
          "aria-selected",
          String(index === select.selectedIndex)
        );

        const disabled = option.disabled || Boolean(group && group.disabled);
        item.setAttribute("aria-disabled", String(disabled));

        if (disabled) item.classList.add("is-disabled");

        item.addEventListener("pointerdown", event => {
          event.preventDefault();
        });

        item.addEventListener("click", () => {
          if (disabled) return;
          choose(index);
        });

        menu.appendChild(item);
        optionNodes[index] = item;
      });

      syncValue();
    }

    function highlight(index) {
      const available = enabledIndices();
      if (!available.length) return;

      if (!available.includes(index)) {
        index = available[0];
      }

      activeIndex = index;

      optionNodes.forEach((node, nodeIndex) => {
        if (!node) return;
        node.classList.toggle("is-active", nodeIndex === activeIndex);
        node.setAttribute(
          "aria-selected",
          String(nodeIndex === select.selectedIndex)
        );
      });

      const activeNode = optionNodes[activeIndex];
      if (activeNode) {
        trigger.setAttribute("aria-activedescendant", activeNode.id);
        activeNode.scrollIntoView({ block: "nearest" });
      }
    }

    function openMenu() {
      if (select.disabled) return;

      renderOptions();
      wrapper.classList.add("is-open");
      trigger.setAttribute("aria-expanded", "true");
      menu.setAttribute("aria-hidden", "false");

      const current = enabledIndices().includes(select.selectedIndex)
        ? select.selectedIndex
        : enabledIndices()[0];

      highlight(current);
    }

    function closeMenu() {
      wrapper.classList.remove("is-open");
      trigger.setAttribute("aria-expanded", "false");
      menu.setAttribute("aria-hidden", "true");
      trigger.removeAttribute("aria-activedescendant");
      activeIndex = -1;
    }

    function choose(index) {
      const option = select.options[index];
      if (!option || option.disabled) return;

      const group = option.parentElement;
      if (group && group.disabled) return;

      select.selectedIndex = index;
      select.dispatchEvent(new Event("input", { bubbles: true }));
      select.dispatchEvent(new Event("change", { bubbles: true }));

      syncValue();
      closeMenu();
      trigger.focus();
    }

    function moveActive(direction) {
      const available = enabledIndices();
      if (!available.length) return;

      let position = available.indexOf(activeIndex);
      if (position < 0) position = available.indexOf(select.selectedIndex);
      if (position < 0) position = 0;

      position = (position + direction + available.length) % available.length;
      highlight(available[position]);
    }

    function handleTypeahead(character) {
      typeahead += character.toLowerCase();

      window.clearTimeout(typeaheadTimer);
      typeaheadTimer = window.setTimeout(() => {
        typeahead = "";
      }, 650);

      const available = enabledIndices();
      if (!available.length) return;

      const start = Math.max(0, available.indexOf(activeIndex) + 1);
      const ordered = available.slice(start).concat(available.slice(0, start));

      const match = ordered.find(index =>
        getOptions()[index].textContent.trim().toLowerCase().startsWith(typeahead)
      );

      if (match !== undefined) highlight(match);
    }

    trigger.addEventListener("click", () => {
      if (wrapper.classList.contains("is-open")) {
        closeMenu();
      } else {
        openMenu();
      }
    });

    trigger.addEventListener("keydown", event => {
      switch (event.key) {
        case "ArrowDown":
          event.preventDefault();
          if (!wrapper.classList.contains("is-open")) openMenu();
          else moveActive(1);
          break;
        case "ArrowUp":
          event.preventDefault();
          if (!wrapper.classList.contains("is-open")) openMenu();
          else moveActive(-1);
          break;
        case "Home":
          if (wrapper.classList.contains("is-open")) {
            event.preventDefault();
            const first = enabledIndices()[0];
            if (first !== undefined) highlight(first);
          }
          break;
        case "End":
          if (wrapper.classList.contains("is-open")) {
            event.preventDefault();
            const available = enabledIndices();
            if (available.length) highlight(available[available.length - 1]);
          }
          break;
        case "Enter":
        case " ":
          event.preventDefault();
          if (!wrapper.classList.contains("is-open")) openMenu();
          else if (activeIndex >= 0) choose(activeIndex);
          break;
        case "Escape":
          if (wrapper.classList.contains("is-open")) {
            event.preventDefault();
            closeMenu();
          }
          break;
        case "Tab":
          closeMenu();
          break;
        default:
          if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
            if (!wrapper.classList.contains("is-open")) {
              openMenu();
              activeIndex = -1;
            }

            handleTypeahead(event.key);
          }
      }
    });

    select.addEventListener("change", () => {
      syncValue();
      renderOptions();
    });

    select.addEventListener("invalid", () => {
      trigger.focus();
    });

    const observer = new MutationObserver(() => {
      renderOptions();
      syncValue();
    });

    observer.observe(select, {
      attributes: true,
      attributeFilter: ["disabled"],
      childList: true,
      subtree: true,
      characterData: true
    });

    if (select.form) {
      select.form.addEventListener("reset", () => {
        window.setTimeout(() => {
          syncValue();
          renderOptions();
          closeMenu();
        }, 0);
      });
    }

    document.addEventListener("pointerdown", event => {
      if (!wrapper.contains(event.target)) closeMenu();
    });

    document.addEventListener("focusin", event => {
      if (!wrapper.contains(event.target)) closeMenu();
    });

    renderOptions();
    syncValue();
  }

  function initAll() {
    document.querySelectorAll(SELECTOR).forEach(initSelect);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAll, { once: true });
  } else {
    initAll();
  }
})();
