// src/components/LanguagesCarousel.jsx
import { useLayoutEffect, useRef, useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "./languagesCarousel.css";

export default function LanguagesCarousel({ items, speedSeconds = 26 }) {
  const groupRef = useRef(null);
  const [shiftPx, setShiftPx] = useState(0);

  const slugify = (name) => name.toLowerCase().replace(/\s+/g, "-");
  const navigate = useNavigate();

  const [openName, setOpenName] = useState(null);
  const [isTouch, setIsTouch] = useState(false);

  const location = useLocation();

  useEffect(() => { 
    const mq = window.matchMedia("(hover: none)");
    const update = () => setIsTouch(mq.matches);
    update();
    mq.addEventListener?.("change", update);
    return () => mq.removeEventListener?.("change", update);
  }, []);

  useLayoutEffect(() => {
    if (!groupRef.current) return;

    const measure = () => {
      setShiftPx(groupRef.current.scrollWidth);
    };

    measure();

    const ro = new ResizeObserver(measure);
    ro.observe(groupRef.current);

    window.addEventListener("resize", measure);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, []);

  return (
    <section className="langCarousel" aria-label="Programming languages carousel">
      <div className="langCarousel__viewport">
        <div
          className="langCarousel__track"
          style={{
            ["--speed"]: `${speedSeconds}s`,
            ["--shift"]: `${shiftPx}px`,
          }}
        >
          {/* 1) Ryhmä (mitataan tästä leveys) */}
          <div className="langCarousel__group" ref={groupRef}>
            {items.map((lang) => {
              const path = `/languages/${slugify(lang.id)}`;
              const isOpen = openName === lang.name; // ADDED: open state for this card

              return (
                <article
                  className={`langCard ${isOpen ? "isOpen" : ""}`} // ADDED: class toggles tooltip on touch
                  key={`a-${lang.name}`}
                  tabIndex={0}
                  role="link"
                  aria-label={`Open ${lang.name}`}
                  aria-expanded={isOpen} // ADDED: a11y state for expanded tooltip
                  onClick={() => {
                    if (!isTouch) { // ADDED: desktop -> navigate immediately
                      navigate(path, { state: { from: location.pathname } });
                      return;
                    }

                    // ADDED: touch -> 1st tap opens, 2nd tap navigates
                    if (!isOpen) setOpenName(lang.name);
                    else navigate(path, { state: { from: location.pathname } });
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      navigate(path, { state: { from: location.pathname } });
                    }
                  }}
                >
                  <div className="langCard__header">
                    <img
                      className="langCard__icon"
                      src={lang.icon}
                      alt={`${lang.name} logo`}
                      loading="lazy"
                      draggable="false"
                    />
                    <h3 className="langCard__name">{lang.name}</h3>
                  </div>

                  <div className="langCard__tooltip">
                    <p className="langCard__desc">{lang.description}</p>
                  </div>
                </article>
              );
            })}
          </div>

          {/* 2) Ryhmä (identtinen kopio, aria-hidden) */}
          <div className="langCarousel__group" aria-hidden="true">
            {items.map((lang) => (
              <article className="langCard" key={`b-${lang.name}`} tabIndex={-1}>
                <div className="langCard__header">
                  <img
                    className="langCard__icon"
                    src={lang.icon}
                    alt=""
                    loading="lazy"
                    draggable="false"
                    aria-hidden="true"
                  />
                  <h3 className="langCard__name">{lang.name}</h3>
                </div>

                <div className="langCard__tooltip">
                  <p className="langCard__desc">{lang.description}</p>
                </div>
              </article>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
