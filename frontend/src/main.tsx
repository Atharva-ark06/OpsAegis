import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./style.css";
// Load after the base stylesheet so shared metallic action styles win consistently.
import "./components/ui/metallic-button.css";
ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
