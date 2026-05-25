export function buildReportingContactsPrompt(input: {
  registrar_name: string | null;
  abuse_contact: string | null;
  abuse_portal: string | null;
  brand_contact: string | null;
  cert_contact: string | null;
  cert_name: string | null;
  cert_country: string | null;
  anti_fraud: string | null;
  
}) {
  return `
You are formatting reporting guidance for a phishing analyst.
Use only the provided contacts. Reference the CERT/CSIRT by name when giving advice.
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
