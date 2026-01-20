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

  function slugify(id) {
    return id.toLowerCase().replace(/\s+/g, "-");
  }

  const techIconBySlug = languages.reduce((acc, lang) => {
    acc[slugify(lang.id)] = lang.icon;
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
            aria-label={`${t.common.open} ${lang.id}`}
          >
            <img
              src={lang.icon}
              alt={`${lang.name} ${t.common.icon}`}
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
          const isSchool = project.type === t.projects.school;


          return (
            <Link
              key={project.id} 
              to={`/projects/${project.id}`}
              className="projectCard"
              aria-label={`${t.common.open} ${project.name}`}
            >
              <div className="projectHeader">
                <div className="projectName">{project.name}</div>

                <div className="projectDescription">{project.description}</div>
              </div>

              <div className="projectFooter">
                <div className="projectTechRow" aria-label={`${project.name} ${t.common.technologies}`}>
                  {project.technologies.map((tech) => {
                    const icon = techIconBySlug[slugify(tech)];
                    if (!icon) return null;
                    return (
                      <img
                        key={tech}
                        src={icon}
                        alt={`${tech} ${t.common.icon}`}
                        className="projectTechIcon"
                        loading="lazy"
                        title={tech}
                      />
                    );
                  })}
                </div>
                {project.type && (
                  <div className={`projectTag ${isSchool ? "tagSchool" : "tagPersonal"}`}>
                    {project.type}
                  </div>
                )}
              </div>
            </Link>
          );
        })}
      </div>
    </main>
  );
}
