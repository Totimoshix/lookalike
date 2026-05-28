import { useState } from "react";
import type { AnalysisResult } from "@capstone/shared";

type ReportingContactsCardProps = {
  result: AnalysisResult;
};

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable
    }
  };

  return (
    <button
      className={copied ? "copy-button copied" : "copy-button"}
      onClick={handleCopy}
      type="button"
      aria-label={copied ? "Copied!" : `Copy ${value}`}
      title={copied ? "Copied!" : "Copy to clipboard"}
    >
      {copied ? "✓" : "⎘"}
    </button>
  );
}

function ContactRow({
  value,
  fallback,
}: {
  value: string | null | undefined;
  fallback: string;
}) {
  if (!value) return <p className="contact-missing">{fallback}</p>;
  const isEmail = value.includes("@");
  return (
    <p className="contact-row-copyable">
      <span className="contact-row-value">{value}</span>
      {isEmail && <CopyButton value={value} />}
    </p>
  );
}

export function ReportingContactsCard({ result }: ReportingContactsCardProps) {
  const contacts = result.reporting_contacts;
  const auth = contacts.local_authorities;

  const csirtLabel = auth.csirt_name ?? "CERT/CSIRT";
  const csirtCountry =
    auth.csirt_country && auth.csirt_country !== "GLOBAL"
      ? ` (${auth.csirt_country})`
      : "";

  return (
    <section className="panel">
      <div className="panel-head">
        <h3>Reporting Contacts</h3>
      </div>
      <div className="contact-grid">
        <article>
          <p className="eyebrow">Registrar</p>
          <p>{contacts.registrar_information.registrar_name ?? "Unknown"}</p>
          <ContactRow
            value={contacts.registrar_information.abuse_contact}
            fallback="No abuse email found"
          />
          <p>{contacts.registrar_information.abuse_portal ?? "No abuse portal found"}</p>
        </article>
        <article>
          <p className="eyebrow">Brand Protection</p>
          <ContactRow
            value={contacts.brand_protection.brand_contact}
            fallback="No brand contact available"
          />
          <ContactRow
            value={contacts.brand_protection.cert_contact}
            fallback="No CERT contact available"
          />
          <ContactRow
            value={contacts.brand_protection.apwg_contact}
            fallback="No APWG contact available"
          />
        </article>
        <article>
          <p className="eyebrow">
            {csirtLabel}{csirtCountry}
          </p>
          <ContactRow value={auth.csirt} fallback="No CSIRT contact available" />
          {auth.csirt_portal ? (
            <a
              className="contact-link"
              href={auth.csirt_portal}
              target="_blank"
              rel="noreferrer noopener"
            >
              Report via portal ↗
            </a>
          ) : (
            <p className="contact-secondary">
              No public portal — escalate via{" "}
              <a
                className="contact-link"
                href="https://apwg.org/reportphishing/"
                target="_blank"
                rel="noreferrer noopener"
              >
                APWG ↗
              </a>{" "}
              or{" "}
              <a
                className="contact-link"
                href="https://www.interpol.int/Contacts/Contact-INTERPOL"
                target="_blank"
                rel="noreferrer noopener"
              >
                INTERPOL ↗
              </a>
            </p>
          )}
          <p className="contact-secondary">
            {auth.anti_fraud ?? "No anti-fraud contact available"}
          </p>
        </article>
      </div>
      <div className="highlight-list">
        {contacts.notes.map((note) => (
          <p className="highlight-chip" key={note}>
            {note}
          </p>
        ))}
      </div>
    </section>
  );
}
