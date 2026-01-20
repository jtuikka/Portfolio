import { useMemo, useRef} from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";
import { getProjects } from "../data/projects";
import { getLanguages } from "../data/languages";
import { getTools } from "../data/tools";


function slugify(id) {
  return String(id || "").toLowerCase().replace(/\s+/g, "-");
}

function isVideoUrl(url) {
  const u = String(url || "").toLowerCase();
  return (
    u.endsWith(".mp4") ||
    u.endsWith(".webm") ||
    u.endsWith(".ogg") ||
    u.includes("youtube.com") ||
    u.includes("youtu.be") ||
    u.includes("vimeo.com")
  );
}

function getYouTubeId(url) {
  const u = String(url || "");
  // youtu.be/<id>
  const short = u.match(/youtu\.be\/([a-zA-Z0-9_-]{6,})/);
  if (short?.[1]) return short[1];
  // youtube.com/watch?v=<id>
  const long = u.match(/[?&]v=([a-zA-Z0-9_-]{6,})/);
  if (long?.[1]) return long[1];
  // youtube.com/embed/<id>
  const emb = u.match(/youtube\.com\/embed\/([a-zA-Z0-9_-]{6,})/);
  if (emb?.[1]) return emb[1];
  return null;
}

function normalizeMedia(media) {
  // Tukee: "" | string | string[] | { images?: string[], videos?: string[] }
  if (!media) return { images: [], videos: [] };

  if (typeof media === "string") {
    const url = media.trim();
    if (!url) return { images: [], videos: [] };
    return isVideoUrl(url) ? { images: [], videos: [url] } : { images: [url], videos: [] };
  }

  if (Array.isArray(media)) {
    const images = [];
    const videos = [];
    for (const item of media) {
      if (!item) continue;
      (isVideoUrl(item) ? videos : images).push(item);
    }
    return { images, videos };
  }

  if (typeof media === "object") {
    const images = Array.isArray(media.images) ? media.images.filter(Boolean) : [];
    const videos = Array.isArray(media.videos) ? media.videos.filter(Boolean) : [];
    return { images, videos };
  }

  return { images: [], videos: [] };
}

export default function ProjectDetail() {
  const { slug } = useParams();
  const { language } = useLanguage();
  const t = translations[language];
  const navigate = useNavigate();
  const location = useLocation();

  const projects = useMemo(() => getProjects(t), [t]);
  const project = projects.find((p) => p.id === slug);

  const languages = useMemo(() => getLanguages(t), [t]);
  const tools = useMemo(() => getTools(t), [t]);

  // ✅ Swipe (mobiili) - Move hooks before any conditional returns
  const touchStart = useRef({ x: 0, y: 0, t: 0 });

  const techBySlug = useMemo(() => {
  const map = {};

  for (const lang of languages) {
    map[slugify(lang.id)] = {
      name: lang.name,
      icon: lang.icon,
    };
  }
  
  for (const tool of tools) {
  map[slugify(tool.id)] = {
      name: tool.name,
      icon: tool.icon,
    };
  }

  return map;
}, [languages, tools]);



  // ✅ Prev/Next projekti (wrap-around)
  const { prevProject, nextProject } = useMemo(() => {
    const currentIndex = projects.findIndex((p) => p.id === slug);

    if (currentIndex === -1 || projects.length === 0) {
      return { prevProject: null, nextProject: null };
    }

    const prevIndex = (currentIndex - 1 + projects.length) % projects.length;
    const nextIndex = (currentIndex + 1) % projects.length;

    return {
      prevProject: projects[prevIndex],
      nextProject: projects[nextIndex],
    };
  }, [projects, slug]);

  const handleBack = () => {
    if (location.state?.from) navigate(-1);
    else navigate("/languages");
  };

  if (!project) {
    return (
      <main className="mainContent">
        <div className="rightSidebar">
          <h1>{t.projects.notFound}</h1>
          <p>{t.projects.projectNotFound}</p>
          <button className="backLink" type="button" onClick={handleBack}>
            ← {t.languages.back}
          </button>
        </div>
      </main>
    );
  }

  const goPrevProject = () => {
    if (prevProject) navigate(`/projects/${prevProject.id}`);
  };

  const goNextProject = () => {
    if (nextProject) navigate(`/projects/${nextProject.id}`);
  };

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
      // swipe vasemmalle -> seuraava projekti
      goNextProject();
    } else {
      // swipe oikealle -> edellinen projekti
      goPrevProject();
    }
  };

  const { images, videos } = normalizeMedia(project.media);

  return (
    <main className="mainContent">
      <div
        className="rightSidebar"
        onTouchStart={onTouchStart}
        onTouchEnd={onTouchEnd}
      >
        <button className="backLink" type="button" onClick={handleBack}>
          ← {t.languages.title2}
        </button>

        {/* ✅ Sama tyyli kuin LanguageDetail: vasen teksti, oikea “paneeli” */}
        <div className="projectTopGrid">
          {/* VASEN */}
          <div className="projectMainHeader">
            <h1 className="projectDetailTitle">{project.name}</h1>
            <p className="projectDetailDescription">{project.descriptionLong}</p>

            {/* ✅ Git-linkki vain jos löytyy */}
            {project.link ? (
              <a
                className="projectGitButton"
                href={project.link}
                target="_blank"
                rel="noreferrer"
              >
                <img
                  src="https://github.com/github/docs/raw/main/assets/images/site/favicon.ico"
                  alt={t.home.github}
                  className="projectGitIcon"
                />
                {t.projects.viewOnGithub}
              </a>
            ) : null}

            {project.thesis_link && (
              <a
                className="projectGitButton"
                href={project.thesis_link}
                target="_blank"
                rel="noreferrer"
              >
                📄 {t.projects.readThesis}
              </a>
            )}
          </div>

          {/* OIKEA */}
          <div className="projectTechBlock">
            <h2 className="projectTechTitle">{t.projects.technologies}</h2>

            <div className="projectTechRow" aria-label={`${project.name} ${t.common.technologies}`}>
              {(project.technologies || []).map((tech) => {
                const data = techBySlug[slugify(tech)];

                if (!data?.icon) {
                  return (
                    <span key={tech} className="projectTag">
                      {tech}
                    </span>
                  );
                }

                return (
                  <span key={tech} className="techIconWrap">
                    <img
                      src={data.icon}
                      alt={data.name}
                      className="projectTechIcon"
                      loading="lazy"
                    />
                    <span className="techTooltip">{data.name}</span>
                  </span>
                );
              })}
            </div>
          </div>
        </div>

        {/* ✅ Media vain jos sitä on */}
        {(videos.length > 0 || images.length > 0) ? (
          <section className="projectMediaSection">
            <h2 className="projectMediaTitle">{t.projects.mediaTitle}</h2>

            {/* Videot */}
            {videos.length > 0 ? (
              <div className="projectMediaGrid">
                {videos.map((url) => {
                  const yt = getYouTubeId(url);
                  if (yt) {
                    return (
                      <div key={url} className="projectMediaItem">
                        <iframe
                          className="projectMediaEmbed"
                          src={`https://www.youtube.com/embed/${yt}`}
                          title="YouTube video"
                          frameBorder="0"
                          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                          allowFullScreen
                        />
                      </div>
                    );
                  }

                  // mp4/webm tms
                  const lower = url.toLowerCase();
                  if (lower.endsWith(".mp4") || lower.endsWith(".webm") || lower.endsWith(".ogg")) {
                    return (
                      <video key={url} className="projectMediaVideo" controls>
                        <source src={url} />
                        {t.projects.videoNotSupported}
                      </video>
                    );
                  }

                  // muu videolinkki (esim. vimeo tms) -> linkkinä
                  return (
                    <a key={url} className="projectGitLink" href={url} target="_blank" rel="noreferrer">
                      {t.projects.videoLink} →
                    </a>
                  );
                })}
              </div>
            ) : null}

            {/* Kuvat */}
            {images.length > 0 ? (
              <div className="projectMediaGrid">
                {images.map((url) => (
                  <img
                    key={url}
                    src={url}
                    alt={t.projects.projectMediaAlt}
                    className="projectMediaImage"
                    loading="lazy"
                  />
                ))}
              </div>
            ) : null}
          </section>
        ) : null}
        {/* ✅ Edellinen / Seuraava projekti (wrap-around) */}
        {projects.length > 1 && prevProject && nextProject ? (
          <div className="languageNavButtons">
            <button className="languageNavButton prev" type="button" onClick={goPrevProject}>
              ← {prevProject.name}
            </button>
            <button className="languageNavButton next" type="button" onClick={goNextProject}>
              {nextProject.name} →
            </button>
          </div>
        ) : null}
      </div>
    </main>
  );
}
