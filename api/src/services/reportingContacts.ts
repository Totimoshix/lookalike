import type { BrandMatch, ReportingContacts } from "@capstone/shared";
import { brandCatalog } from "../data/brandCatalog.js";
import { registrarContacts } from "../data/registrarContacts.js";
import { buildReportingContactsPrompt } from "../prompts/reportingContacts.js";
import { callBedrockJson } from "./bedrock.js";

export async function buildReportingContacts(input: {
  brandMatch: BrandMatch;
  registrarName: string | null;
}): Promise<ReportingContacts> {
  const brandEntry = brandCatalog.find((entry) => entry.brandName === input.brandMatch.brand_name);
  const registrar = input.registrarName ? registrarContacts[input.registrarName.toLowerCase()] : undefined;

  const base: ReportingContacts = {
    registrar_information: {
      registrar_name: input.registrarName,
      abuse_contact: registrar?.abuseContact ?? null,
      abuse_portal: registrar?.abusePortal ?? null,
      whois_lookup_url: "https://lookup.icann.org/en"
    },
    brand_protection: {
      brand_contact: brandEntry?.securityContact ?? null,
      cert_contact: "cert@cert-c.ca",
      apwg_contact: "phishing@apwg.org",
      google_safe_browsing_report: "https://safebrowsing.google.com/safebrowsing/report_phish/",
      microsoft_submission: "https://www.microsoft.com/en-us/wdsi/filesubmission"
    },
    local_authorities: {
      anti_fraud: "report@antifraudcentre-centreantifraude.gc.ca",
      csirt: "contact@cyber.gc.ca"
    },
    notes: []
  };

  const llmNotes = await callBedrockJson<{ notes: string[] }>({
    promptName: "reporting_contacts",
    prompt: buildReportingContactsPrompt({
      registrar_name: base.registrar_information.registrar_name,
      abuse_contact: base.registrar_information.abuse_contact,
      abuse_portal: base.registrar_information.abuse_portal,
      brand_contact: base.brand_protection.brand_contact,
      cert_contact: base.brand_protection.cert_contact,
      anti_fraud: base.local_authorities.anti_fraud
    }),
    validator: (value) => {
      if (!value || typeof value !== "object" || !Array.isArray((value as { notes?: unknown }).notes)) {
        return null;
      }
      return {
        notes: (value as { notes: string[] }).notes.slice(0, 4)
      };
    }
  });

  return {
    ...base,
    notes:
      llmNotes?.notes && llmNotes.notes.length > 0
        ? llmNotes.notes
        : [
            "Report to the registrar using the listed abuse channel when available.",
            "Notify the brand security contact if the site is impersonating a known brand.",
            "Submit the URL to APWG and Google Safe Browsing for wider takedown visibility."
          ]
  };
}
