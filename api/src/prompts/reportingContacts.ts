export function buildReportingContactsPrompt(input: {
  registrar_name: string | null;
  abuse_contact: string | null;
  abuse_portal: string | null;
  brand_contact: string | null;
  cert_contact: string | null;
  anti_fraud: string | null;
}) {
  return `
You are formatting reporting guidance for a phishing analyst.
Use only the provided contacts.
Return valid JSON only.

Contacts:
${JSON.stringify(input, null, 2)}

Return JSON:
{
  "notes": [
    "Short actionable reporting note"
  ]
}
`.trim();
}
