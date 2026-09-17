import { useState, useEffect, type ReactNode } from "react";
import ShopPage from "./pages/ShopPage";
import DashboardShell from "./pages/dashboard/DashboardShell";
import NewScan from "./pages/dashboard/NewScan";
import Scanning from "./pages/dashboard/Scanning";
import Results from "./pages/dashboard/Results";
import History from "./pages/dashboard/History";
import Settings from "./pages/dashboard/Settings";

type Route = "shop" | "dashboard/new-scan" | "dashboard/scanning" | "dashboard/results" | "dashboard/history" | "dashboard/settings";

function parseHash(): Route {
  const hash = window.location.hash.replace(/^#\/?/, "");
  if (hash.startsWith("dashboard/new-scan")) return "dashboard/new-scan";
  if (hash.startsWith("dashboard/scanning")) return "dashboard/scanning";
  if (hash.startsWith("dashboard/results")) return "dashboard/results";
  if (hash.startsWith("dashboard/history")) return "dashboard/history";
  if (hash.startsWith("dashboard/settings")) return "dashboard/settings";
  if (hash.startsWith("dashboard")) return "dashboard/new-scan";
  return "shop";
}

function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(parseHash);
  useEffect(() => {
    const onHashChange = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);
  return route;
}

export default function App() {
  const route = useHashRoute();

  if (route === "shop") return <ShopPage />;

  let screen: ReactNode;
  if (route === "dashboard/new-scan") screen = <NewScan />;
  else if (route === "dashboard/scanning") screen = <Scanning />;
  else if (route === "dashboard/results") screen = <Results />;
  else if (route === "dashboard/history") screen = <History />;
  else screen = <Settings />;

  return <DashboardShell>{screen}</DashboardShell>;
}
