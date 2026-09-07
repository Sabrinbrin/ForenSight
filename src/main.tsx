import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
import "./ios.css";
import "./refined.css";
import "./route-aesthetic.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode><App /></StrictMode>,
);
