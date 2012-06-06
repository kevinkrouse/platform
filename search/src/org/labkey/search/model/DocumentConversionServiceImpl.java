/*
 * Copyright (c) 2011-2012 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.labkey.search.model;

import org.apache.batik.transcoder.TranscoderException;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.PNGTranscoder;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.attachments.DocumentConversionService;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.util.List;

/**
 * User: adam
 * Date: 10/12/11
 * Time: 5:33 PM
 */
public class DocumentConversionServiceImpl implements DocumentConversionService
{
    private static final int DEFAULT_USER_SPACE_UNIT_DPI = 72;     // From PDFBox PDPage

    @Override
    public void svgToPng(String svg, OutputStream os) throws TranscoderException
    {
        svgToPng(svg, os, null);
    }

    // If height is provided, we'll auto-size keeping the aspect ratio; if null we'll use the dimensions in the SVG
    @Override
    public void svgToPng(String svg, OutputStream os, @Nullable Float height) throws TranscoderException
    {
        TranscoderInput xIn = new TranscoderInput(new StringReader(svg));
        TranscoderOutput xOut = new TranscoderOutput(os);

        PNGTranscoder transcoder = new PNGTranscoder();
        transcoder.addTranscodingHint(PNGTranscoder.KEY_BACKGROUND_COLOR, java.awt.Color.WHITE);

        if (null != height)
            transcoder.addTranscodingHint(PNGTranscoder.KEY_HEIGHT, height);

        transcoder.transcode(xIn, xOut);
    }

    @Override
    public BufferedImage pdfToImage(InputStream pdfStream, int page)
    {
        // This matches the PDFBox PDPage.convertToImage defaults... these probably aren't ideal for all PDFs and target image formats
        return pdfToImage(pdfStream, page, BufferedImage.TYPE_USHORT_565_RGB, 2 * DEFAULT_USER_SPACE_UNIT_DPI);
    }

    @Override
    public BufferedImage pdfToImage(InputStream pdfStream, int page, int bufferedImageType, int resolution)
    {
        try
        {
            PDDocument document = PDDocument.load(pdfStream);

            // PDFBox extracts blank images from secure PDF; detect and use static thumbnail instead
            if (document.isEncrypted())
                return null;

            List<PDPage> pages = document.getDocumentCatalog().getAllPages();

            if (pages.size() >= page)
            {
                PDPage pdPage = pages.get(page);
                return pdPage.convertToImage(bufferedImageType, resolution);
            }
        }
        catch (IOException e)
        {
            // Fall through
        }

        return null;
    }
}
