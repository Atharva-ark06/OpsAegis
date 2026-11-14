import { PlaybookWorkflowDesigner } from "./components/ui/playbook-workflow-designer-wrapper";

export function PlaybooksPanel(_props: { incidents: import("./api").Incident[]; user: import("./api").User }) {
  return <PlaybookWorkflowDesigner />;
}
