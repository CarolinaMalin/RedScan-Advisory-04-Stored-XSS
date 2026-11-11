# Advisory 03 — Stored Cross-Site Scripting (XSS) in `admin/tax_classes.php`

**Researcher:** Carolina Malinconico  
**Instructor:** Carlos Tuma  
**Course:** Report Profissional de CVE 2.0 — RedScan Academy  
**Environment:** Modified eCommerce Shopsoftware, local Docker lab

> **Scope:** Reproduced in the training Docker image. Upstream impact and CVE assignment have not been established.

---

## 1. Summary

Stored Cross-Site Scripting (Stored XSS) was reproduced in the Tax Classes administration feature of the Modified eCommerce Shopsoftware Docker laboratory. User-controlled multilingual tax-class titles and descriptions were saved and later rendered as executable HTML. Benign JavaScript alert dialogs were observed for both fields. This advisory follows the structure of the instructor’s Advisory 03 while adding the researcher’s practical proof-of-concept evidence.

## 2. Identification

| Field | Value |
|---|---|
| Product | Modified eCommerce Shopsoftware |
| Component | Administration — Tax Classes |
| Affected file / endpoint | admin/tax_classes.php / /admin/tax_classes.php |
| Version tested | 3.3.0 rev 16825 — training Docker image |
| Input fields | tax_class_title, tax_class_description |
| Record selector | tID (specific record ID not established in supplied evidence) |
| Vulnerability | Stored Cross-Site Scripting (XSS) |
| CWE | CWE-79 |
| OWASP | A03:2021 — Injection |
| CVSS | Not assessed |
| Environment | Local Docker instance, localhost:8080 |

## 3. Analyzed endpoint

GET /admin/tax_classes.php

The administrative interface allows authorized users to create, edit, inspect, and delete multilingual tax-class records. The laboratory tests used a dedicated fictitious tax class (Sin Tax) rather than modifying production records.

## 4. Fields involved

Both tax_class_title and tax_class_description are accepted through POST and processed by xtc_db_prepare_input(). Values are combined into language-keyed strings (language::value separated by ||) and saved to TABLE_TAX_CLASS. The analyzed update path includes lines 69–94; the create path includes lines 36–62.

```php
$tax_class_title = xtc_db_prepare_input($_POST['tax_class_title']);
$tax_class_description = xtc_db_prepare_input($_POST['tax_class_description']);
```

```php
$tax_class_title_array[] = $key . '::' . $value;
$tax_class_description_array[] = $key . '::' . $value;
```

```php
$tax_class_title = implode('||', $tax_class_title_array);
$tax_class_description = implode('||', $tax_class_description_array);
```

The application then persists the values using xtc_db_perform(TABLE_TAX_CLASS, $sql_data_array, ...).

## 5. Technical evidence

### 5.1. Title rendering in the list (line 160)

```php
echo parse_multi_language_value($tax_classes['tax_class_title'], $_SESSION['language_code']);
```

### 5.2. Title rendering in the details panel (line 238)

```php
$heading[] = array('text' => '<b>' . parse_multi_language_value($tcInfo->tax_class_title, $_SESSION['language_code']) . '</b>');
```

### 5.3. Description rendering (line 243)

```php
$contents[] = array('text' => '<br />' . TEXT_INFO_CLASS_DESCRIPTION . '<br />' . parse_multi_language_value($tcInfo->tax_class_description, $_SESSION['language_code']));
```

### 5.4. Title rendering in the delete-confirmation view (line 232)

```php
$contents[] = array('text' => '<br /><b>' . parse_multi_language_value($tcInfo->tax_class_title, $_SESSION['language_code']) . '</b>');
```

The researcher reported an alert in the deletion workflow; a dedicated screenshot of that confirmation step was not provided. The precise triggering sink in the list/details/edit views has not been isolated by instrumented tracing.

### 5.5. Multilingual decoding helper

The instructor’s source review identifies parse_multi_language_value() in inc/parse_multi_language_value.inc.php, which returns decode_htmlentities() for the selected language. The latter calls html_entity_decode() in inc/html_encoding.php. Decoding entities does not provide safe HTML output encoding.

```php
return decode_htmlentities($lang_array[$lang_code]);
// decode_htmlentities():
return html_entity_decode($string, $flags, $encoding);
```

### 5.6. Editing form versus display output

The instructor’s analysis notes that xtc_draw_input_field() uses encode_htmlspecialchars(trim($value)) for the input value attribute. This escaping in the edit control does not protect separate HTML-body rendering sinks.

## 6. Practical proof of concept

The following tests were performed in a local, authorized Docker lab. The JavaScript was limited to an alert and did not transmit data externally.

1. Sign in to the administrative interface and open /admin/tax_classes.php.
2. Create or edit a fictitious tax class; use the Description field for a benign image-error alert payload and save.
3. Select the record and observe an alert displaying “Teste XSS Carolina”; re-open the record and observe the alert again.
4. In a separate test, place an analogous alert payload in the Title field and a harmless text value in Description.
5. Observe the “XSS-Titulo-Carolina” alert in the class interface and while the edit view is open.
6. The researcher also reported an alert on entering the delete-confirmation workflow; this observation has no separate screenshot.
```html
<img src=x onerror=alert('Teste XSS Carolina')>
<img src=x onerror=alert('XSS-Titulo-Carolina')>
```

## 7. Root cause

Untrusted, persisted multilingual values are decoded and inserted into HTML without context-appropriate output encoding at the identified sinks. Consequently, an HTML event-handler payload may be interpreted by the browser. Input preparation for database use and escaping of input-field attributes are not substitutes for HTML-body output encoding.

## 8. Potential impact and limitations

A user with permission to modify tax classes could store script-bearing content that runs when another authorized administrator views the affected record. Actual impact depends on role permissions, the page context, and browser defenses. No credential theft, remote exploitation, or impact on an unmodified upstream release was demonstrated. The training image may differ from the official product. No CVE identifier or CVSS score is claimed.

## 9. Recommendations

- Apply context-appropriate output encoding to tax-class titles and descriptions at every HTML rendering sink.
- For HTML text nodes, use an encoding equivalent to htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8").
- Review uses of parse_multi_language_value() and html_entity_decode() before HTML output; avoid decoding untrusted data immediately before rendering.
- Retain authorization controls and add regression tests covering multilingual values and HTML metacharacters.
- Consider a restrictive Content Security Policy as defense in depth, not as a replacement for escaping.
- Remove the laboratory alert payloads after capturing evidence.
## 10. Evidence and validation status

POST input and persistence: Confirmed by source review

Description XSS: Reproduced; screenshot evidence

Title XSS: Reproduced; screenshot evidence

Repeated execution: Observed in laboratory

Edit view alert: Screenshot evidence

Delete confirmation alert: Researcher reported; no dedicated screenshot

Official upstream version affected: Not established

CVE assignment: Not established

## Appendix A — Laboratory screenshots

Images retained from the researcher’s earlier report. Some show initial setup or contextual steps rather than a distinct exploit sink.

### Evidence image 1

![Laboratory evidence evidence-01](images/evidence-01.png)

Source: researcher’s previous laboratory report.

### Evidence image 2

![Laboratory evidence evidence-02](images/evidence-02.png)

Source: researcher’s previous laboratory report.

### Evidence image 3

![Laboratory evidence evidence-03](images/evidence-03.png)

Source: researcher’s previous laboratory report.

### Evidence image 4

![Laboratory evidence evidence-04](images/evidence-04.png)

Source: researcher’s previous laboratory report.

### Evidence image 5

![Laboratory evidence evidence-05](images/evidence-05.png)

Source: researcher’s previous laboratory report.

### Evidence image 6

![Laboratory evidence evidence-06](images/evidence-06.png)

Source: researcher’s previous laboratory report.

### Evidence image 7

![Laboratory evidence evidence-07](images/evidence-07.png)

Source: researcher’s previous laboratory report.

### Evidence image 8

![Laboratory evidence evidence-08](images/evidence-08.png)

Source: researcher’s previous laboratory report.
