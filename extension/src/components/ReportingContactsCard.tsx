import type { AnalysisResult } from "@capstone/shared";

type ReportingContactsCardProps = {
  result: AnalysisResult;
};

export function ReportingContactsCard({ result }: ReportingContactsCardProps) {
  const contacts = result.reporting_contacts;

  return (
    <section className="panel">
      <div className="panel-head">
        <h3>Reporting Contacts</h3>
      </div>
      <div className="contact-grid">
        <article>
          <p className="eyebrow">Registrar</p>
          <p>{contacts.registrar_information.registrar_name ?? "Unknown"}</p>
          <p>{contacts.registrar_information.abuse_contact ?? "No abuse email found"}</p>
          <p>{contacts.registrar_information.abuse_portal ?? "No abuse portal found"}</p>
        </article>
        <article>
          <p className="eyebrow">Brand Protection</p>
          <p>{contacts.brand_protection.brand_contact ?? "No brand contact available"}</p>
          <p>{contacts.brand_protection.cert_contact ?? "No CERT contact available"}</p>
          <p>{contacts.brand_protection.apwg_contact ?? "No APWG contact available"}</p>
        </article>
        <article>
          <p className="eyebrow">Authorities</p>
          <p>{contacts.local_authorities.anti_fraud ?? "No anti-fraud contact available"}</p>
          <p>{contacts.local_authorities.csirt ?? "No CSIRT contact available"}</p>
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

