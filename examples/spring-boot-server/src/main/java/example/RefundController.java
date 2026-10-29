package example;

import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RefundController {
    /** Only reached when the filter allowed the request: the proof matches exactly this body. */
    @PostMapping("/refunds")
    public Map<String, Object> refund(@RequestBody Map<String, Object> body) {
        return Map.of("refunded", body.get("amount"), "currency", body.get("currency"));
    }
}
