"use client";

import * as React from "react";
import { motion, useReducedMotion } from "motion/react";

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
  const reduceMotion = useReducedMotion();
  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: reduceMotion ? 0 : 0.012 },
    },
  };
  const letterAnimation = {
    hidden: { opacity: 0, filter: "blur(8px)", y: reduceMotion ? 0 : 3 },
    show: {
      opacity: 1,
      filter: "blur(0px)",
      y: 0,
      transition: { duration: reduceMotion ? 0 : 0.28, ease: "easeOut" as const },
    },
  };
  const Heading = as === "h2" ? motion.h2 : motion.h1;

  return (
    <Heading
      variants={container}
      initial={reduceMotion ? false : "hidden"}
      animate="show"
      aria-label={text}
      className={className}
    >
      {text.split("").map((char, index) => (
        <motion.span key={index} variants={letterAnimation} aria-hidden="true">
          {char === " " ? "\u00A0" : char}
        </motion.span>
      ))}
    </Heading>
  );
}
