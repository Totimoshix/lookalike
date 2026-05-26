import type { AnalysisResult } from "@capstone/shared";
import { generateAnalystReportHtml } from "../lib/htmlReport";

type PdfExportButtonProps = {
  result: AnalysisResult;
};

export function PdfExportButton({ result }: PdfExportButtonProps) {
  const handleExport = () => {
    const html = generateAnalystReportHtml(result);
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${result.normalized_domain}-threat-report.html`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button className="ghost-button" onClick={handleExport} type="button">
      Export report (HTML → PDF)
    </button>
  );
}
