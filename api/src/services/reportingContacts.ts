import type { BrandMatch, ReportingContacts } from "@capstone/shared";
import { brandCatalog } from "../data/brandCatalog.js";
import { registrarContacts } from "../data/registrarContacts.js";
import { buildReportingContactsPrompt } from "../prompts/reportingContacts.js";
import { callBedrockJson } from "./bedrock.js";
import { resolveCsirt, brandCountryMap } from "../data/csirtContacts.js";

export async function buildReportingContacts(input: {
  brandMatch: BrandMatch;
  registrarName: string | null;
  registrantCountry: string | null;
  tld: string | null;
}): Promise<ReportingContacts> {
  const brandEntry = brandCatalog.find((entry) => entry.brandName === input.brandMatch.brand_name);
  const registrar = input.registrarName ? registrarContacts[input.registrarName.toLowerCase()] : undefined;
  const csirt = resolveCsirt(input.registrantCountry, input.tld, input.brandMatch.brand_name);

  const base: ReportingContacts = {
    registrar_information: {
      registrar_name: input.registrarName,
      abuse_contact: registrar?.abuseContact ?? null,
      abuse_portal: registrar?.abusePortal ?? null,
      whois_lookup_url: "https://lookup.icann.org/en"
    },
    brand_protection: {
      brand_contact: brandEntry?.securityContact ?? null,
      cert_contact: csirt.contact,
      apwg_contact: "phishing@apwg.org",
      google_safe_browsing_report: "https://safebrowsing.google.com/safebrowsing/report_phish/",
      microsoft_submission: "https://www.microsoft.com/en-us/wdsi/filesubmission"
    },
    local_authorities: {
      anti_fraud: resolveAntiFraud(input.registrantCountry, input.tld, input.brandMatch.brand_name),
      csirt: csirt.contact,
      csirt_name: csirt.name,
      csirt_country: csirt.country,
      csirt_portal: csirt.portal
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
      cert_name: csirt.name,
      cert_country: csirt.country,
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
            `File an incident report with ${csirt.name} using the contact listed under Authorities.`,
            "Submit the URL to APWG and Google Safe Browsing for wider takedown visibility."
          ]
  };
}
function resolveAntiFraud(
  registrantCountry: string | null,
  tld: string | null,
  brandName?: string | null
): string | null {
  const antiFraudMap: Record<string, string> = {
    ca: "report@antifraudcentre-centreantifraude.gc.ca",
    us: "ic3.gov/complaint (FBI IC3)",
    mx: "condusef.gob.mx (CONDUSEF)",
    gb: "report@actionfraud.police.uk",
    de: "bka.de/cybercrime (BKA)",
    fr: "cybermalveillance.gouv.fr",
    nl: "politie.nl/aangifte (Dutch Police)",
    se: "polisen.se/anmal-brott",
    no: "politiet.no/tjenester/anmeldelse",
    fi: "poliisi.fi/rikosilmoitus",
    dk: "politi.dk/anmeld-en-forbrydelse",
    ch: "cybercrime.ch (fedpol)",
    at: "bmi.gv.at/cybercrime",
    be: "police.be/cybercrime",
    es: "incibe.es/linea-de-ayuda-en-ciberseguridad (017)",
    it: "commissariatodips.it",
    pl: "cert.pl/zglos",
    pt: "cncs.gov.pt/denunciar",
    ie: "garda.ie/en/crime/cyber-crime/",
    ro: "politiaromana.ro/cybercrime",
    cz: "policie.cz/cybercrime",
    ru: "mvd.ru (Russian Ministry of Internal Affairs)",
    au: "cyber.gov.au/report-and-recover/report (ReportCyber)",
    nz: "cert.nz/report",
    jp: "cybercrime.go.jp (National Police Agency)",
    kr: "ecrm.police.go.kr (Korean Cyber Bureau)",
    cn: "12321.cn (CNCERT Hotline)",
    in: "cybercrime.gov.in",
    sg: "iwitness.spf.gov.sg",
    hk: "cybercrime.gov.hk (Hong Kong Police)",
    tw: "165.gov.tw (Anti-Fraud Hotline)",
    my: "ccid.rmp.gov.my (Royal Malaysia Police)",
    id: "patrolisiber.id (Indonesian National Police)",
    il: "gov.il/cybercrime",
    ae: "ecrime.ae (Dubai Police)",
    za: "saps.gov.za/cybercrime",
    br: "safernet.org.br/denuncie",
    ar: "argentina.gob.ar/justicia/derechofacil/cybercrimen",
    cl: "ciberseguridad.gob.cl/reporte",
  };

  const countryKey = (registrantCountry ?? "").toLowerCase();
  if (countryKey && antiFraudMap[countryKey]) {
    return antiFraudMap[countryKey];
  }

  const tldKey = (tld ?? "").replace(/^\./, "").toLowerCase();
  if (tldKey.length === 2 && antiFraudMap[tldKey]) {
    return antiFraudMap[tldKey];
  }

  if (brandName && brandCountryMap[brandName]) {
    const brandKey = brandCountryMap[brandName];
    if (antiFraudMap[brandKey]) {
      return antiFraudMap[brandKey];
    }
  }

  return "report@antifraudcentre-centreantifraude.gc.ca";
}
