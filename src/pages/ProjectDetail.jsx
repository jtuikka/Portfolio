import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";
import { getProjects } from "../data/projects";

export default function ProjectDetail() {
  const { slug } = useParams();
  const { language } = useLanguage();
  const t = translations[language];
  const navigate = useNavigate();
  const location = useLocation();

  const projects = getProjects(t);


  const project = projects.find((p) => p.id === slug);


  const handleBack = () => {
    if (location.state?.from) navigate(-1);
    else navigate("/languages");
  };

  if (!project) {
    return (
      <main className="mainContent">
        <div className="rightSidebar">
          <h1>Not found</h1>
          <p>Tätä projektia ei löytynyt.</p>
          <button
            className="backLink"
            type="button"
            onClick={handleBack}
          >
            ← Back
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="mainContent">
      <div className="rightSidebar">
        <button className="backLink" type="button" onClick={handleBack}>
          ← {t.languages.title2}
        </button>

        <div className="projectDetailHeader">
          <h1 className="projectDetailTitle">{project.name}</h1>
        </div>
      </div>
    </main>
  );
}
