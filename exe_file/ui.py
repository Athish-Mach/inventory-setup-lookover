from __future__ import annotations

import logging
import queue
import tkinter as tk
from typing import Any

import customtkinter as ctk

from config import APP_NAME
from database import SupabaseDatabase
from monitor import AdvisoryMatch, AdvisoryMonitor, AdvisorySnapshot, MonitorStatus
from product_store import LocalProductStore
from utils import (
    advisory_fixed_releases,
    advisory_key,
    advisory_last_updated,
    display_affected_products,
    parse_affected_products,
    safe_advisory_text,
    validate_product_name,
)

logger = logging.getLogger(__name__)

# Ensure dark appearance is set before creating any CTk widgets
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class CiscoAdvisoryApp(ctk.CTk):
    def __init__(self, database: SupabaseDatabase, product_store: LocalProductStore) -> None:
        super().__init__()
        self.database = database
        self.product_store = product_store
        self.queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.monitor = AdvisoryMonitor(
            database=database,
            get_monitored_products=self.product_store.get_products,
            on_status=lambda status: self.queue.put(("status", status)),
            on_advisories=lambda snapshot: self.queue.put(("advisories", snapshot)),
        )
        self.all_rows: dict[str, dict[str, Any]] = {}
        self.new_or_updated_keys: set[str] = set()
        self.selected_product: str | None = None
        self.product_buttons: list[ctk.CTkButton | ctk.CTkLabel] = []
        self.card_frames: list[ctk.CTkFrame] = []
        self.card_expanded: set[str] = set()

        self._configure_window()
        self._build_layout()
        self.monitor.start()
        self.after(150, self._process_queue)

    def _configure_window(self) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title(APP_NAME)
        self.geometry("1200x800")
        self.minsize(980, 640)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def _break_long_words(self, text: str, limit: int = 40) -> str:
        if not text:
            return text
        parts = []
        for word in str(text).split(" "):
            if len(word) <= limit:
                parts.append(word)
            else:
                chunks = [word[i : i + limit] for i in range(0, len(word), limit)]
                parts.append("\u200b".join(chunks))
        return " ".join(parts)

    def _shorten(self, text: str, limit: int = 300) -> str:
        if not text:
            return text
        s = str(text).strip()
        if len(s) <= limit:
            return s
        cut = s[:limit]
        # avoid cutting mid-word
        if " " in cut:
            cut = cut.rsplit(" ", 1)[0]
        return cut + "…"

    def _build_layout(self) -> None:
        self.sidebar = ctk.CTkFrame(self, width=320, corner_radius=0, fg_color="#0b0f16")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)

        title = ctk.CTkLabel(
            self.sidebar,
            text="Product",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w",
        )
        title.grid(row=0, column=0, padx=24, pady=(28, 10), sticky="ew")

        self.product_entry = ctk.CTkEntry(
            self.sidebar,
            placeholder_text="Cisco ISE, Windows Server, VMware ESXi",
            height=42,
        )
        self.product_entry.grid(row=1, column=0, padx=24, pady=(0, 12), sticky="ew")
        self.product_entry.bind("<Return>", lambda _event: self._add_product())

        self.add_button = ctk.CTkButton(
            self.sidebar,
            text="Start Monitoring",
            height=42,
            command=self._add_product,
        )
        self.add_button.grid(row=2, column=0, padx=24, pady=(0, 12), sticky="ew")

        products_heading = ctk.CTkLabel(
            self.sidebar,
            text="Products in Advisories",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w",
        )
        products_heading.grid(row=3, column=0, padx=24, pady=(0, 10), sticky="ew")

        self.products_frame = ctk.CTkScrollableFrame(
            self.sidebar,
            fg_color="#10141c",
            corner_radius=8,
            height=230,
        )
        self.products_frame.grid(row=4, column=0, padx=24, pady=(0, 20), sticky="nsew")

        self.connection_label = ctk.CTkLabel(
            self.sidebar,
            text="Connected to Supabase",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#7dd3fc",
            anchor="w",
        )
        self.connection_label.grid(row=7, column=0, padx=24, pady=(8, 0), sticky="ew")

        self.status_label = ctk.CTkLabel(
            self.sidebar,
            text="Waiting for updates...",
            text_color="#cbd5e1",
            wraplength=260,
            anchor="w",
            justify="left",
        )
        self.status_label.grid(row=8, column=0, padx=24, pady=(4, 20), sticky="ew")

        self.main = ctk.CTkFrame(self, corner_radius=0, fg_color="#0b0f16")
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self.main, fg_color="transparent")
        header.grid(row=0, column=0, padx=28, pady=(24, 12), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        heading = ctk.CTkLabel(
            header,
            text="Latest Matching Advisories",
            font=ctk.CTkFont(size=24, weight="bold"),
            anchor="w",
        )
        heading.grid(row=0, column=0, sticky="w")

        self.add_advisory_button = ctk.CTkButton(
            header,
            text="+ Add Advisory",
            width=130,
            height=34,
            command=self._open_advisory_form,
        )
        self.add_advisory_button.grid(row=0, column=1, sticky="e")

        self.search_entry = ctk.CTkEntry(
            self.main,
            placeholder_text="Search by product, summary, or name",
            height=40,
        )
        self.search_entry.grid(row=1, column=0, padx=28, pady=(0, 14), sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda _event: self._render_cards())

        self.cards_frame = ctk.CTkScrollableFrame(
            self.main,
            fg_color="#0b0f16",
            corner_radius=0,
        )
        self.cards_frame.grid(row=2, column=0, padx=20, pady=(0, 12), sticky="nsew")
        self.cards_frame.grid_columnconfigure(0, weight=1)

        self.empty_label = ctk.CTkLabel(
            self.cards_frame,
            text="No matching advisories yet.",
            text_color="#94a3b8",
            font=ctk.CTkFont(size=15),
        )
        self.empty_label.grid(row=0, column=0, padx=8, pady=40, sticky="ew")

        self.status_bar = ctk.CTkFrame(self.main, height=38, corner_radius=0, fg_color="#111827")
        self.status_bar.grid(row=3, column=0, sticky="ew")
        self.status_bar.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.status_connected = ctk.CTkLabel(self.status_bar, text="Connected to Supabase")
        self.status_checking = ctk.CTkLabel(self.status_bar, text="Waiting for updates...")
        self.status_checked = ctk.CTkLabel(self.status_bar, text="Last checked: Never")
        self.status_count = ctk.CTkLabel(self.status_bar, text="Products: 0")
        self.status_connected.grid(row=0, column=0, padx=12, pady=8, sticky="w")
        self.status_checking.grid(row=0, column=1, padx=12, pady=8)
        self.status_checked.grid(row=0, column=2, padx=12, pady=8)
        self.status_count.grid(row=0, column=3, padx=12, pady=8, sticky="e")

    def _add_product(self) -> None:
        raw_value = self.product_entry.get()
        try:
            product_name = validate_product_name(raw_value)
        except ValueError as exc:
            self._set_inline_status(str(exc), is_error=True)
            return

        self.add_button.configure(state="disabled", text="Adding...")
        try:
            added, message = self.product_store.add_product(product_name)
            products = self.product_store.get_products()
            if added:
                self.product_entry.delete(0, tk.END)
            self._update_monitored_count(products)
            self._set_inline_status(message, is_error=not added)
            self.monitor.trigger_check()
        except Exception as exc:
            logger.error("Failed adding product: %s", exc, exc_info=True)
            self._set_inline_status(f"Could not add product: {exc}", is_error=True)
        finally:
            self.add_button.configure(state="normal", text="Start Monitoring")

    def _open_advisory_form(self) -> None:
        form = ctk.CTkToplevel(self)
        form.title("Add Advisory to Supabase")
        form.geometry("560x800")
        form.transient(self)
        form.grab_set()
        form.grid_columnconfigure(0, weight=1)
        form.grid_columnconfigure(1, weight=2)
        form.grid_rowconfigure(8, weight=1)

        heading = ctk.CTkLabel(
            form,
            text="Add Advisory to Supabase",
            font=ctk.CTkFont(size=20, weight="bold"),
            anchor="w",
        )
        heading.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 8), sticky="w")

        description = ctk.CTkLabel(
            form,
            text="Fill in the advisory details below and click Submit. "
            "Affected products may be entered as comma-separated values.",
            text_color="#cbd5e1",
            wraplength=520,
            justify="left",
        )
        description.grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 18), sticky="ew")

        form.grid_rowconfigure(2, weight=1)
        form.grid_rowconfigure(3, weight=1)
        form.grid_rowconfigure(4, weight=1)
        form.grid_rowconfigure(5, weight=1)

        form.id_entry = self._create_labeled_entry(
            form,
            row=2,
            label_text="ID (optional)",
            placeholder="Numeric ID",
        )
        # Pre-fill ID with next available numeric id when possible
        try:
            next_id = self.database.next_advisory_id()
            form.id_entry.insert(0, str(next_id))
        except Exception:
            # If database isn't reachable or the query fails, leave blank
            pass
        form.name_entry = self._create_labeled_entry(
            form,
            row=3,
            label_text="Name",
            placeholder="Advisory title",
        )
        form.products_entry = self._create_labeled_entry(
            form,
            row=4,
            label_text="Affected Products",
            placeholder="Cisco ISE, Windows Server, VMware ESXi",
        )
        form.cve_id_entry = self._create_labeled_entry(
            form,
            row=5,
            label_text="CVE ID (optional)",
            placeholder="CVE-2024-1234",
        )
        form.cvss_score_entry = self._create_labeled_entry(
            form,
            row=6,
            label_text="CVSS Score (optional)",
            placeholder="7.5",
        )
        form.severity_entry = self._create_labeled_entry(
            form,
            row=7,
            label_text="Severity (optional)",
            placeholder="High, Critical, Medium, Low",
        )

        ctk.CTkLabel(form, text="Summary").grid(row=8, column=0, padx=20, pady=(10, 4), sticky="nw")
        # Use dark-themed Text widget so content matches CTk theme
        form.summary_text = tk.Text(
            form,
            height=5,
            width=40,
            wrap="word",
            bg="#0b0f16",
            fg="#e6eef8",
            insertbackground="#e6eef8",
            relief="flat",
        )
        form.summary_text.grid(row=8, column=1, padx=20, pady=(10, 4), sticky="nsew")

        ctk.CTkLabel(form, text="Workarounds").grid(row=9, column=0, padx=20, pady=(10, 4), sticky="nw")
        form.workarounds_text = tk.Text(
            form,
            height=5,
            width=40,
            wrap="word",
            bg="#0b0f16",
            fg="#e6eef8",
            insertbackground="#e6eef8",
            relief="flat",
        )
        form.workarounds_text.grid(row=9, column=1, padx=20, pady=(10, 4), sticky="nsew")

        form.status_label = ctk.CTkLabel(
            form,
            text="",
            text_color="#cbd5e1",
            wraplength=520,
            anchor="w",
            justify="left",
        )
        form.status_label.grid(row=10, column=0, columnspan=2, padx=20, pady=(10, 4), sticky="ew")

        submit_button = ctk.CTkButton(
            form,
            text="Submit Advisory",
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            command=lambda: self._submit_advisory(form),
        )
        submit_button.grid(row=11, column=0, columnspan=2, padx=20, pady=(12, 20), sticky="ew")

    def _create_labeled_entry(
        self,
        parent: tk.Misc,
        row: int,
        label_text: str,
        placeholder: str,
    ) -> ctk.CTkEntry:
        ctk.CTkLabel(parent, text=label_text).grid(row=row, column=0, padx=20, pady=(10, 4), sticky="w")
        entry = ctk.CTkEntry(parent, placeholder_text=placeholder, height=34)
        entry.grid(row=row, column=1, padx=20, pady=(10, 4), sticky="ew")
        return entry

    def _available_card_width(self) -> int:
        # Estimate available width for cards based on overall window size and sidebar
        try:
            self.update_idletasks()
            total = self.winfo_width() or 1200
            sidebar = self.sidebar.winfo_width() or 320
            available = max(320, total - sidebar - 120)
            return available
        except Exception:
            return 760

    def _submit_advisory(self, form: tk.Toplevel) -> None:
        raw_id = form.id_entry.get().strip()
        name = form.name_entry.get().strip()
        summary = form.summary_text.get("1.0", "end").strip()
        workarounds = form.workarounds_text.get("1.0", "end").strip()
        products = [product.strip() for product in form.products_entry.get().split(",") if product.strip()]
        cve_id = form.cve_id_entry.get().strip()
        cvss_score = form.cvss_score_entry.get().strip()
        severity = form.severity_entry.get().strip()

        if not name:
            form.status_label.configure(text="Name is required.", text_color="#f87171")
            return
        if not products:
            form.status_label.configure(text="Enter at least one affected product.", text_color="#f87171")
            return

        advisory: dict[str, Any] = {
            "name": name,
            "summary": summary,
            "workarounds": workarounds,
            "affected_products": products,
        }

        if cve_id:
            advisory["cve_id"] = cve_id
        if cvss_score:
            try:
                advisory["cvss_score"] = float(cvss_score)
            except ValueError:
                form.status_label.configure(text="CVSS Score must be a valid number.", text_color="#f87171")
                return
        if severity:
            advisory["severity"] = severity

        if raw_id:
            try:
                advisory["id"] = int(raw_id)
            except ValueError:
                form.status_label.configure(text="ID must be a number.", text_color="#f87171")
                return

        try:
            self.database.insert_advisory(advisory)
            form.destroy()
            self._set_inline_status("Advisory submitted to Supabase.", is_error=False)
            self.monitor.trigger_check()
        except Exception as exc:
            logger.error("Failed inserting advisory: %s", exc, exc_info=True)
            form.status_label.configure(text=f"Could not submit advisory: {exc}", text_color="#f87171")

    def _process_queue(self) -> None:
        try:
            while True:
                event_type, payload = self.queue.get_nowait()
                if event_type == "status":
                    self._update_status(payload)
                elif event_type == "advisories":
                    self._handle_advisory_snapshot(payload)
                elif event_type == "error":
                    self._set_inline_status(payload, is_error=True)
                    self.add_button.configure(state="normal", text="Start Monitoring")
        except queue.Empty:
            pass
        self.after(150, self._process_queue)

    def _update_status(self, status: MonitorStatus) -> None:
        connected_text = "Connected to Supabase" if status.connected else "Supabase unavailable"
        color = "#7dd3fc" if status.connected else "#f87171"
        self.connection_label.configure(text=connected_text, text_color=color)
        self.status_connected.configure(text=connected_text, text_color=color)
        self.status_label.configure(text=status.message)
        self.status_checking.configure(text=status.message)
        self.status_checked.configure(text=f"Last checked: {status.last_checked}")
        self.status_count.configure(text=f"Products: {status.monitored_count}")

    def _set_inline_status(self, message: str, is_error: bool = False) -> None:
        color = "#f87171" if is_error else "#86efac"
        self.status_label.configure(text=message, text_color=color)
        self.status_checking.configure(text=message, text_color=color)

    def _update_monitored_count(self, products: list[str]) -> None:
        self.status_count.configure(text=f"Monitored: {len(products)}")

    def _handle_advisory_snapshot(self, snapshot: AdvisorySnapshot) -> None:
        self.all_rows = {advisory_key(row): row for row in snapshot.rows}
        self.new_or_updated_keys = snapshot.new_or_updated_keys
        self._render_products(self._all_affected_products())
        self._render_cards()

    def _all_affected_products(self) -> list[str]:
        products_by_key: dict[str, str] = {}
        for row in self.all_rows.values():
            for product in display_affected_products(row.get("affected_products")):
                key = product.casefold()
                if key not in products_by_key:
                    products_by_key[key] = product
        return sorted(products_by_key.values(), key=str.casefold)

    def _render_products(self, products: list[str]) -> None:
        for widget in self.product_buttons:
            widget.destroy()
        self.product_buttons.clear()

        all_button = ctk.CTkButton(
            self.products_frame,
            text="All Products",
            height=34,
            corner_radius=6,
            fg_color="#2563eb" if self.selected_product is None else "#1f2937",
            hover_color="#1d4ed8",
            anchor="w",
            command=lambda: self._select_product(None),
        )
        all_button.grid(row=0, column=0, padx=4, pady=4, sticky="ew")
        self.product_buttons.append(all_button)

        if not products:
            label = ctk.CTkLabel(
                self.products_frame,
                text="No products found yet",
                height=34,
                text_color="#94a3b8",
                anchor="w",
            )
            label.grid(row=1, column=0, padx=4, pady=4, sticky="ew")
            self.product_buttons.append(label)
            return

        for index, product in enumerate(products, start=1):
            selected = self.selected_product == product
            button = ctk.CTkButton(
                self.products_frame,
                text=product,
                height=34,
                corner_radius=6,
                fg_color="#2563eb" if selected else "#1f2937",
                hover_color="#1d4ed8",
                anchor="w",
                command=lambda value=product: self._select_product(value),
            )
            button.grid(row=index, column=0, padx=4, pady=4, sticky="ew")
            self.product_buttons.append(button)

    def _select_product(self, product: str | None) -> None:
        self.selected_product = product
        self._render_products(self._all_affected_products())
        self._render_cards()

    def _render_cards(self) -> None:
        for frame in self.card_frames:
            frame.destroy()
        self.card_frames.clear()
        self.empty_label.grid_forget()

        search = self.search_entry.get().strip().casefold()
        visible_matches = self._visible_advisory_matches(search)
        visible_matches.sort(
            key=lambda match: advisory_last_updated(match.row),
            reverse=True,
        )

        if not visible_matches:
            self.empty_label.grid(row=0, column=0, padx=8, pady=40, sticky="ew")
            return

        for index, match in enumerate(visible_matches):
            card = self._create_card(self.cards_frame, match)
            card.grid(row=index, column=0, padx=8, pady=8, sticky="ew")
            self.card_frames.append(card)

    def _visible_advisory_matches(self, search: str) -> list[AdvisoryMatch]:
        matches: list[AdvisoryMatch] = []
        for key, row in self.all_rows.items():
            affected_products = display_affected_products(row.get("affected_products"))
            if self.selected_product:
                selected = self.selected_product.casefold()
                if selected not in " | ".join(affected_products).casefold():
                    continue
                matched_products = [self.selected_product]
            else:
                matched_products = affected_products

            match = AdvisoryMatch(
                row=row,
                matched_products=matched_products,
                is_new=key in self.new_or_updated_keys,
            )
            if self._matches_search(match, search):
                matches.append(match)
        return matches

    def _matches_search(self, match: AdvisoryMatch, search: str) -> bool:
        if not search:
            return True
        affected_products = parse_affected_products(match.row.get("affected_products"))
        display_products = display_affected_products(match.row.get("affected_products"))
        fixed_releases = advisory_fixed_releases(match.row)
        haystack = " ".join(
            [
                safe_advisory_text(match.row, "name", ""),
                safe_advisory_text(match.row, "summary", ""),
                safe_advisory_text(match.row, "cve_id", ""),
                safe_advisory_text(match.row, "cvss_score", ""),
                safe_advisory_text(match.row, "severity", ""),
                " ".join(match.matched_products),
                " ".join(display_products or affected_products),
                " ".join(fixed_releases),
            ]
        ).casefold()
        return search in haystack

    def _create_card(self, parent: ctk.CTkScrollableFrame, match: AdvisoryMatch) -> ctk.CTkFrame:
        border_color = "#38bdf8" if match.is_new else "#273244"
        card = ctk.CTkFrame(parent, fg_color="#151b26", corner_radius=8, border_width=1, border_color=border_color)
        card.grid_columnconfigure(0, weight=1)
        card.grid_columnconfigure(1, weight=0)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.grid(row=0, column=0, padx=18, pady=(16, 6), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        name = safe_advisory_text(match.row, "name", "Unnamed advisory")
        avail = self._available_card_width()
        wrap_name = max(280, avail - 120)
        name = self._break_long_words(name, limit=36)
        name_label = ctk.CTkLabel(
            header,
            text=name,
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w",
            justify="left",
            wraplength=wrap_name,
            text_color="#e6eef8",
        )
        name_label.grid(row=0, column=0, sticky="ew")

        if match.is_new:
            new_label = ctk.CTkLabel(
                header,
                text="NEW",
                width=54,
                height=24,
                corner_radius=6,
                fg_color="#0ea5e9",
                text_color="#ffffff",
                font=ctk.CTkFont(size=12, weight="bold"),
            )
            new_label.grid(row=0, column=1, padx=(12, 0), sticky="ne")

        key = advisory_key(match.row)
        expanded = key in self.card_expanded

        details = {
            "CVE ID": safe_advisory_text(match.row, "cve_id"),
            "CVSS Score": safe_advisory_text(match.row, "cvss_score"),
            "Severity": safe_advisory_text(match.row, "severity"),
            "Summary": safe_advisory_text(match.row, "summary"),
            "Affected Products": ", ".join(display_affected_products(match.row.get("affected_products"))) or "Not provided",
            "Workarounds": safe_advisory_text(match.row, "workarounds"),
            "Fixed Releases": ", ".join(advisory_fixed_releases(match.row)) or "Not provided",
        }

        row_index = 1
        for label, value in details.items():
            title = ctk.CTkLabel(
                card,
                text=label,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#93c5fd",
                anchor="w",
            )
            title.grid(row=row_index, column=0, columnspan=2, padx=18, pady=(8, 0), sticky="ew")
            row_index += 1
            # prepare and break very long words so labels can wrap
            value = str(value or "")
            value = self._break_long_words(value, limit=40)
            wrap_body = max(280, avail - 80)

            # If this is Summary or Workarounds, allow collapse/expand
            if label in ("Summary", "Workarounds"):
                display_text = value if expanded else self._shorten(value, limit=300)
                body = ctk.CTkLabel(
                    card,
                    text=display_text,
                    text_color="#e6eef8",
                    anchor="w",
                    justify="left",
                    wraplength=wrap_body,
                )
                body.grid(row=row_index, column=0, padx=18, pady=(2, 4), sticky="ew")

                # show toggle if original value is long
                if len(value) > 300:
                    btn_text = "Show less" if expanded else "Show more"
                    toggle = ctk.CTkButton(
                        card,
                        text=btn_text,
                        width=88,
                        height=28,
                        fg_color="#1f2937",
                        hover_color="#273244",
                        command=lambda k=key: self._toggle_card(k),
                    )
                    toggle.grid(row=row_index, column=1, padx=(8, 18), pady=(2, 4), sticky="ne")
                row_index += 1
            else:
                body = ctk.CTkLabel(
                    card,
                    text=value or "Not provided",
                    text_color="#e6eef8",
                    anchor="w",
                    justify="left",
                    wraplength=wrap_body,
                )
                body.grid(row=row_index, column=0, columnspan=2, padx=18, pady=(2, 4), sticky="ew")
                row_index += 1

        matched_text = "Matched: " + ", ".join(match.matched_products)
        matched_text = self._break_long_words(matched_text, limit=36)
        matched = ctk.CTkLabel(
            card,
            text=matched_text,
            text_color="#86efac",
            anchor="w",
            font=ctk.CTkFont(size=12, weight="bold"),
            justify="left",
            wraplength=max(280, avail - 80),
        )
        matched.grid(row=row_index, column=0, columnspan=2, padx=18, pady=(8, 16), sticky="ew")
        return card

    def _toggle_card(self, key: str) -> None:
        if key in self.card_expanded:
            self.card_expanded.remove(key)
        else:
            self.card_expanded.add(key)
        self._render_cards()

    def on_close(self) -> None:
        self.monitor.stop()
        self.destroy()
