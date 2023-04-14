import docx

def create_styles(doc):
    styles = doc.styles
    
    # Define finding_name style
    finding_name_style = styles.add_style('finding_name', docx.enum.style.WD_STYLE_TYPE.PARAGRAPH)
    finding_name_style.font.name = 'Calibri (Headings)'
    finding_name_style.font.bold = True
    finding_name_style.font.size = docx.shared.Pt(11)
    finding_name_style.font.color.rgb = docx.shared.RGBColor(74, 193, 224)  # Set font color to #4AC1E0
    finding_name_style.paragraph_format.space_after = docx.shared.Pt(6)
    finding_name_style.paragraph_format.line_spacing_rule = docx.enum.text.WD_LINE_SPACING.AT_LEAST
    finding_name_style.paragraph_format.line_spacing = docx.shared.Pt(14)
    finding_name_style.paragraph_format.keep_together = True
    finding_name_style.paragraph_format.keep_with_next = True

    # Define Details style
    details_style = styles.add_style('details_style', docx.enum.style.WD_STYLE_TYPE.PARAGRAPH)
    details_style.font.name = 'Cambria (Body)'
    details_style.font.bold = True
    details_style.font.size = docx.shared.Pt(9.5)
    details_style.paragraph_format.space_after = docx.shared.Pt(6)
    
    # Define Affected Targets style
    affected_targets_style = styles.add_style('affected_targets_style', docx.enum.style.WD_STYLE_TYPE.PARAGRAPH)
    affected_targets_style.font.name = 'Cambria (Body)'
    affected_targets_style.font.bold = True
    affected_targets_style.font.size = docx.shared.Pt(9.5)
    affected_targets_style.paragraph_format.space_after = docx.shared.Pt(6)
    
    # Define description style
    description_style = styles.add_style('description', docx.enum.style.WD_STYLE_TYPE.PARAGRAPH)
    description_style.font.name = 'Cambria (Body)'
    description_style.font.size = docx.shared.Pt(9.5)
    description_style.paragraph_format.space_after = docx.shared.Pt(6)

    # Define plugin_output style
    plugin_output_style = styles.add_style('plugin_output', docx.enum.style.WD_STYLE_TYPE.PARAGRAPH)
    plugin_output_style.font.name = 'Courier New'
    plugin_output_style.font.size = docx.shared.Pt(9.5)
    plugin_output_style.paragraph_format.space_after = docx.shared.Pt(6)
    plugin_output_style.paragraph_format.left_indent = docx.shared.Cm(0.2)
    plugin_output_style.paragraph_format.right_indent = docx.shared.Cm(0.2)

    # Define targets style
    targets_style = styles.add_style('targets', docx.enum.style.WD_STYLE_TYPE.PARAGRAPH)
    targets_style.font.name = 'Cambria (Body)'
    targets_style.font.size = docx.shared.Pt(9.5)
    targets_style.paragraph_format.space_after = docx.shared.Pt(6)

    # Define bullet style
    bullet_style = styles.add_style('bullet_style', docx.enum.style.WD_STYLE_TYPE.PARAGRAPH)
    bullet_style.font.name = 'Cambria (Body)'
    bullet_style.font.size = docx.shared.Pt(9.5)
    bullet_style.paragraph_format.left_indent = docx.shared.Cm(0)
    bullet_style.paragraph_format.first_line_indent = docx.shared.Cm(-0.6)
