import * as React from "react";

type HeadingLevel = "h1" | "h2";

export function BlurredStagger({
  text,
  className = "text-base",
  as = "h1",
}: {
  text: string;
  className?: string;
  as?: HeadingLevel;
}) {
  const Heading = as;

  return (
    <Heading aria-label={text} className={className}>
      {text.split("").map((char, index) => (
        <span
          key={index}
          className="ops-blurred-stagger-char"
          style={{ animationDelay: `${index * 12}ms` }}
          aria-hidden="true"
        >
          {char === " " ? "\\u00A0" : char}
        </span>
      ))}
    </Heading>
  );
}
