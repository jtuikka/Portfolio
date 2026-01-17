import { Link } from "react-router-dom";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";
import { getLanguages } from "../data/languages";
import { getProjects } from "../data/projects";

export default function Languages() {
  const { language } = useLanguage();
  const t = translations[language];

  const languages = getLanguages(t);
  const projects = getProjects(t);

  function slugify(name) {
    return name.toLowerCase().replace(/\s+/g, "-");
  }

  // technology id -> icon (assumes project.technologies items match lang.id)
  const techIconById = languages.reduce((acc, lang) => {
    acc[lang.id] = lang.icon;
    return acc;
  }, {});

  return (
    <main className="pageContent">
      <h1 className="languagesTitle">{t.languages.title}</h1>

      <div className="languagesGrid">
        {languages.map((lang) => (
          <Link
            key={lang.id}
            to={`/languages/${slugify(lang.id)}`}
            className="languageCard"
            aria-label={`Open ${lang.id}`}
          >
            <img
              src={lang.icon}
              alt={`${lang.name} icon`}
              className="languageIcon"
              loading="lazy"
            />
            <div className="languageName">{lang.name}</div>
          </Link>
        ))}
      </div>

      <h1 className="projectsTitle">{t.languages.title2}</h1>

      <div className="projectsGrid">
        {projects.map((project) => {
          const isSchool = project.type === "school";

          return (
            <div key={project.name} className="projectCard">
              <div className="projectHeader">
                <div className="projectName">{project.name}</div>

                <div className="projectDescription">{project.description}</div>
              </div>

              <div className="projectFooter">
                <div className="projectTechRow" aria-label={`${project.name} technologies`}>
                  {project.technologies.map((tech) => {
                    const icon = techIconById[tech];
                    if (!icon) return null;
                    return (
                      <img
                        key={tech}
                        src={icon}
                        alt={`${tech} icon`}
                        className="projectTechIcon"
                        loading="lazy"
                        title={tech}
                      />
                    );
                  })}
                </div>

                <div className={`projectTag ${isSchool ? "tagSchool" : "tagPersonal"}`}>
                  {project.type}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </main>
  );
}
