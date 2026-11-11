# Advisory 04 — Stored Cross-Site Scripting (XSS) in Sales Report

## Summary

A stored cross-site scripting (XSS) condition was confirmed in the administrative Sales Report of **modified eCommerce Shopsoftware v3.3.0, revision 16825**, in a local Docker-based test environment. The report renders an order item's stored product name as HTML without context-appropriate output encoding. When a harmless proof-of-concept payload was placed in the `orders_products.products_name` field of a test order and the administrator opened the detailed Sales Report, the browser executed the payload and displayed the expected JavaScript alert.

**Scope limitation:** The payload was inserted directly into the local test database. This demonstrates a vulnerable rendering sink and execution of stored JavaScript, **not** an independently verified, remotely reachable injection path. No claim is made that an unauthenticated customer or another lower-privileged actor can control this field in a default installation.

## Tested Environment

| Field | Details |
|---|---|
| Application | modified eCommerce Shopsoftware |
| Tested version | 3.3.0, revision 16825 |
| Component | Administrative Sales Report |
| Affected page | `admin/stats_sales_report.php` |
| Related report class | `admin/includes/classes/sales_report.php` |
| Stored field tested | `orders_products.products_name` |
| Database record | Local test order `orders_id = 2`, `orders_products_id = 1` |
| Environment | Local Docker installation, accessed through `http://localhost:8080/` |
| Weakness category | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| Validation | Browser JavaScript alert observed in the administrative report |
| Disclosure status | Laboratory finding; no vendor notification or CVE assignment claimed |

## Technical Description

In the detailed Sales Report view, the application prints a product model and product name directly into an HTML anchor element. The relevant rendering logic is equivalent to:

```php
<a href="<?php echo xtc_catalog_href_link('product_info.php?products_id=' . $info[$i]['pid']); ?>" target="_blank">
  <?php echo ((xtc_not_null($info[$i]['pmodel'])) ? $info[$i]['pmodel'] . ' : ' : '') . $info[$i]['pname']; ?>
</a>
```

The values are output without HTML escaping at this rendering point. The same report also prints product attribute labels and values without visible context-appropriate encoding:

```php
echo $attr['options'][$x] . ': ' . $attr['options_values'][$x];
```

The test confirmed execution through the **product name** field. The product model and attribute fields were identified as additional potentially unsafe output locations through code review, but were **not separately validated** by the proof of concept documented here.

The report obtains order-product details through the Sales Report class, which reads order data from the database. The tested product name was stored in `orders_products.products_name`, rather than being taken directly from a current HTTP query parameter.

## Preconditions and Attack-Surface Limitations

- An administrator or other user authorized to view the detailed Sales Report must load the affected page.
- A malicious HTML/JavaScript string must already be present in an order-product field consumed by the report.
- In this proof of concept, the string was inserted through direct database access available only in the local lab.
- A customer-facing, unauthenticated, or lower-privileged route for storing the string **has not been established**. Practical exploitability and severity depend on whether such a route exists and on the privileges of the person viewing the report.

## Steps to Reproduce — Authorized Local Laboratory

1. Start the local modified eCommerce Shopsoftware v3.3.0 rev 16825 installation.
2. Create an ordinary test product with model `REDSCAN-001` and a nonzero price.
3. Place a test order for the product. In the documented run, the order contained two units, used local pickup and cash payment, and completed successfully.
4. Confirm that the order is visible under **Administration → Sales Report**, with a date range covering the order and a detailed view such as **Details with value**.
5. Identify the test order-product record. In this run, it was `orders_id = 2` and `orders_products_id = 1`.
6. In the **local test database only**, set `orders_products.products_name` for that exact record to the following benign alert payload:

   ```html
   <img src=x onerror=alert("RedScan-XSS")>
   ```

   Example PHP CLI command for the documented Docker container:

   ```bash
   docker exec modified-shop-web php -r '
   require "/var/www/html/includes/configure.php";
   $db = new mysqli(DB_SERVER, DB_SERVER_USERNAME, DB_SERVER_PASSWORD, DB_DATABASE);
   $payload = "<img src=x onerror=alert(\"RedScan-XSS\")>";
   $stmt = $db->prepare("UPDATE orders_products SET products_name = ? WHERE orders_products_id = 1 AND orders_id = 2");
   $stmt->bind_param("s", $payload);
   $stmt->execute();
   echo "Rows updated: " . $stmt->affected_rows . PHP_EOL;
   '
   ```

7. Reload `http://localhost:8080/admin/stats_sales_report.php` while authenticated as an administrator, retain the detailed report view, and select **Update**.
8. Observe the browser alert with the text **`RedScan-XSS`**.

### Observed Result

The browser displayed a JavaScript alert labeled `RedScan-XSS` while rendering the Sales Report. This confirms that the stored product-name value was interpreted as executable markup in the tested administrative page.

### Expected Secure Behavior

The report should display the product name as literal text. For example, the `<img ...>` string should appear as text rather than creating an HTML element or executing an event handler.

## Evidence

The accompanying eight-page document, **`Documento sem título (1).docx`**, contains the laboratory screenshots and code excerpts:

| Page | Evidence |
|---|---|
| 1–4 | Inspection of the Sales Report source and unescaped product-name/model and attribute output |
| 5–7 | Test product setup, checkout configuration, and order confirmation |
| 8 | Completed order, detailed Sales Report, database record inspection, and the `RedScan-XSS` browser alert |

The final screenshot on page 8 is the decisive runtime evidence. The code review and alert together support the conclusion that the tested report output is vulnerable to stored-script execution when an order-product name contains HTML/JavaScript.


### Screenshot evidence (GitHub relative paths)

**Order confirmation (test item and model):**

![Test order confirmation](evidence/01-order-confirmation.png)

**Order successfully created:**

![Order success](evidence/02-order-success.png)

**Sales Report renders the stored order-product name:**

![Sales report details](evidence/03-sales-report-details.png)

**Database query identifies the test order-product record:**

![Order product database record](evidence/04-order-database-record.png)

**Confirmed execution — browser alert `RedScan-XSS`:**

![Stored XSS alert confirmed in the Sales Report](evidence/05-stored-xss-alert-confirmed.png)

## Potential Impact

If an attacker-controlled value can reach the affected order-product field through an application feature, an administrator viewing the detailed report could execute attacker-supplied JavaScript in the administrative origin. Depending on browser controls, session protections, and application permissions, this could enable unauthorized actions in the administrator's context or access to data exposed to client-side scripts.

**These downstream effects were not tested.** The laboratory demonstrated a JavaScript alert only. No data extraction, privilege escalation, session theft, or remotely accessible injection path was demonstrated.

## Root Cause

The affected HTML output concatenates database-backed product fields directly into the response without encoding for the HTML text context. Storing a value in a database does not make it safe for subsequent HTML rendering.

## Recommended Remediation

1. Apply context-appropriate HTML output encoding to product names, models, and attribute names/values before inserting them into the HTML response. In PHP, a suitable approach for plain HTML text is:

   ```php
   echo htmlspecialchars((string) $info[$i]['pname'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
   ```

   Ensure that the chosen character encoding matches the application's actual output encoding. Apply the same protection to `pmodel`, attribute option labels, and attribute values.
2. Audit other administrative views that render order snapshots, product fields, and exported content. CSV exports require separate spreadsheet-formula-injection considerations; HTML escaping alone is not a CSV defense.
3. Review the data-entry and order-creation paths to establish which roles can influence the stored fields, and apply appropriate validation without relying on input filtering as the primary XSS defense.
4. Consider a restrictive Content Security Policy as defense in depth, while retaining output encoding as the primary fix.
5. Add regression tests that store HTML-like text in order-product fields and verify it is displayed literally in all report detail modes.

## Suggested Validation After a Fix

Repeat the local proof of concept using the same test record. The report should display the payload as escaped text and must not produce a JavaScript alert. Recheck the model and attribute display paths independently.

## Cleanup of the Test Record

After collecting evidence, restore the local order-product name:

```bash
docker exec modified-shop-web php -r '
require "/var/www/html/includes/configure.php";
$db = new mysqli(DB_SERVER, DB_SERVER_USERNAME, DB_SERVER_PASSWORD, DB_DATABASE);
$name = "RedScan XSS Test Product";
$stmt = $db->prepare("UPDATE orders_products SET products_name = ? WHERE orders_products_id = 1 AND orders_id = 2");
$stmt->bind_param("s", $name);
$stmt->execute();
echo "Rows restored: " . $stmt->affected_rows . PHP_EOL;
'
```

Cleanup is provided as a procedure; **its successful execution has not been verified** in the evidence supplied.

## Responsible Disclosure Notes

This report documents a finding in an isolated, authorized local environment. Before making claims about a broadly exploitable vulnerability, validate whether a lower-privileged or external user can cause malicious content to be stored in the affected order-product fields. Consider contacting the project maintainers privately before publishing exploit details. No CVE ID, CVSS score, vendor acknowledgment, or patch status is asserted here.
