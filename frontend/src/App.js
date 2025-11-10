import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import CodeScan from "./pages/CodeScan";
import ExternalScan from "./pages/ExternalScan";
import History from "./pages/History";
import About from "./pages/About";
import "./index.css";

import logo from "./assets/logo (2).png";

function App() {
  return (
    <Router>
      {/* Navbar */}
      <nav className="flex justify-between items-center px-10 py-4 bg-[#031323] shadow-md border-b-2 border-[#456882] sticky top-0 z-50">
        <NavLink to="/" className="flex items-center space-x-3">
          <img
            src={logo}
            alt="DevSecure360 Logo"
            className="h-10 w-auto object-contain"
          />
          <h1 className="font-bold text-2xl text-[#D2C1B6] tracking-wide whitespace-nowrap">
            DevSecure360
          </h1>
          </NavLink>
        <div className="space-x-6 text-lg font-medium">
          {[
            { to: "/", label: "Dashboard" },
            { to: "/code-scan", label: "Code Scan" },
            { to: "/external-scan", label: "External Scan" },
            { to: "/history", label: "History" },
            { to: "/about", label: "About" },
          ].map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `transition-all duration-300 pb-1 ${
                  isActive
                    ? "text-[#F4EBD3] border-b-2 border-[#D2C1B6]"
                    : "text-[#DED3C4] hover:text-[#F4EBD3]"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </div>
      </nav>

      {/* Main layout background */}
      <div className="bg-[#234C6A] min-h-screen text-[#D2C1B6]">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/code-scan" element={<CodeScan />} />
          <Route path="/external-scan" element={<ExternalScan />} />
          <Route path="/history" element={<History />} />
          <Route path="/about" element={<About />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
