import { useMemo, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import { useLocation, useNavigate } from "react-router-dom";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";
import { getLanguages } from "../data/languages";
import { getProjects } from "../data/projects";

function slugify(id) {
  return id.toLowerCase().replace(/\s+/g, "-");
}

export default function LanguageDetail() {
  const { slug } = useParams();
  const { language } = useLanguage();
  const t = translations[language];

  const location = useLocation();
  const navigate = useNavigate();

  const languages = useMemo(() => getLanguages(t), [t]);
  const lang = languages.find((l) => slugify(l.id) === slug);

  const handleBack = () => {
    if (location.state?.from) navigate(-1);
    else navigate("/languages");
  };

  // ✅ Projektit ja filtteröinti kielen perusteella
  const allProjects = getProjects(t);
  const relatedProjects = allProjects.filter((p) =>
    (p.technologies || []).some((tech) => slugify(tech) === slug)
  );

 // ✅ Prev/Next kieli (wrap-around)
const { prevLang, nextLang } = useMemo(() => {
  const currentIndex = languages.findIndex((l) => slugify(l.id) === slug);

  // jos slug ei löydy, älä kaada appia
  if (currentIndex === -1 || languages.length === 0) {
    return { prevLang: null, nextLang: null };
  }

  const prevIndex = (currentIndex - 1 + languages.length) % languages.length;
  const nextIndex = (currentIndex + 1) % languages.length;

  return {
    prevLang: languages[prevIndex],
    nextLang: languages[nextIndex],
  };
}, [languages, slug]);


  const goPrev = () => {
    if (prevLang) navigate(`/languages/${slugify(prevLang.id)}`);
  };

  const goNext = () => {
    if (nextLang) navigate(`/languages/${slugify(nextLang.id)}`);
  };

  // ✅ Swipe (mobiili)
  const touchStart = useRef({ x: 0, y: 0, t: 0 });

  const onTouchStart = (e) => {
    const t0 = e.touches[0];
    touchStart.current = { x: t0.clientX, y: t0.clientY, t: Date.now() };
  };

  const onTouchEnd = (e) => {
    const t1 = e.changedTouches[0];
    const dx = t1.clientX - touchStart.current.x;
    const dy = t1.clientY - touchStart.current.y;
    const dt = Date.now() - touchStart.current.t;

    // Kynnykset: riittävän pitkä vaakapyyhkäisy, ei “vahingossa” scrollista
    const MIN_DIST = 60;      // px
    const MAX_OFF_AXIS = 80;  // px
    const MAX_TIME = 700;     // ms

    if (dt > MAX_TIME) return;
    if (Math.abs(dx) < MIN_DIST) return;
    if (Math.abs(dy) > MAX_OFF_AXIS) return;

    if (dx < 0) {
      // swipe vasemmalle -> seuraava
      goNext();
    } else {
      // swipe oikealle -> edellinen
      goPrev();
    }
  };

  if (!lang) {
    return (
      <main className="mainContent">
        <div className="rightSidebar">
          <h1>{t.languages.notFound}</h1>
          <p>{t.languages.languageNotFound}</p>
          <button className="backLink" type="button" onClick={handleBack}>
            ← {t.languages.back}
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="mainContent">
      {/* Swipe-alue: laita tähän, jos haluat että pyyhkäisy toimii koko sivulla */}
      <div
        className="rightSidebar"
        onTouchStart={onTouchStart}
        onTouchEnd={onTouchEnd}
      >
        <button className="backLink" type="button" onClick={handleBack}>
          ← {t.languages.title}
        </button>

        <div className="languageTopGrid">
          {/* VASEN: KIELI */}
          <div className="languageMainHeader">
            <div className="langHeader">
              <img src={lang.icon} alt="" className="langHeaderIcon" />
              <h1 className="langHeaderTitle">{lang.name}</h1>
            </div>

            <p className="langDescription">{lang.descriptionLong}</p>
          </div>

          {/* OIKEA: KURSSIT */}
          <div className="languageCoursesBlock">
            <h2 className="languageCoursesTitle">{t.languages.coursesTitle}</h2>

            <ul className="languageCoursesList">
              {lang.courses.map((course, index) => (
                <li key={index}>{course}</li>
              ))}
            </ul>
          </div>
        </div>
        <h2 className="languageProjectsTitle">{t.languages.projectsTitle}</h2>

        {relatedProjects.length === 0 ? (
          <p className="languagesIntro">
            {t.languages.noRelatedProjects}
          </p>
        ) : (
          <div className="projectsGrid">
            {relatedProjects.map((p) => (
              <Link key={p.id} to={`/projects/${p.id}`} className="projectCardLink">
                <article key={p.id} className="projectCard">
                  <div className="projectHeader">
                    <div className="projectName">{p.name}</div>
                    <div className="projectDescription">{p.description}</div>
                  </div>

                  <div className="projectFooter">
                    <div className="projectTechRow">
                      {(p.technologies || []).map((tech) => {
                        const techLang = languages.find((l) => slugify(l.id) === slugify(tech));

                        return techLang?.icon ? (
                          <img
                            key={tech}
                            className="projectTechIcon"
                            src={techLang.icon}
                            alt={techLang.name}
                            title={techLang.name}
                          />
                        ) : (
                          <span key={tech} className="projectTag">
                            {tech}
                          </span>
                        );
                      })}
                    </div>
                    {p.type && (
                      <span
                        className={
                          "projectTag " +
                          (p.type === t.projects.school ? "tagSchool" : "tagPersonal")
                        }
                      >
                        {p.type}
                      </span>
                    )}
                  </div>
                </article>
              </Link>
            ))}
          </div>
        )}
         {/* ✅ Edellinen / Seuraava -napit */}
        <div className="languageNavButtons">
          {prevLang && (
            <button className="languageNavButton prev" type="button" onClick={goPrev}>
              ← {prevLang.name}
            </button>
          )}
          {nextLang && (
            <button className="languageNavButton next" type="button" onClick={goNext}>
              {nextLang.name} →
            </button>
          )}
        </div>
      </div>
    </main>
  );
}
