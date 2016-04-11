#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/bitcf.png
ICON_DST=../../src/qt/res/icons/bitcf.ico
convert ${ICON_SRC} -resize 16x16 bitcf-16.png
convert ${ICON_SRC} -resize 32x32 bitcf-32.png
convert ${ICON_SRC} -resize 48x48 bitcf-48.png
convert bitcf-16.png bitcf-32.png bitcf-48.png ${ICON_DST}

