// src/components/LanguagesCarousel.jsx
import { useLayoutEffect, useRef, useState } from "react";
import "./languagesCarousel.css";

export default function LanguagesCarousel({ items, speedSeconds = 26 }) {
  const groupRef = useRef(null);
  const [shiftPx, setShiftPx] = useState(0);

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
            {items.map((lang) => (
              <article className="langCard" key={`a-${lang.name}`} tabIndex={0}>
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
            ))}
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
