// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

#include "common/configure.h"
#include "vm/vm.h"

#include <gtest/gtest.h>

#include <vector>

namespace {

using namespace WasmEdge;

template <typename T>
void assertOk(WasmEdge::Expect<T> Res, const char *Message) {
  if (!Res) {
    EXPECT_TRUE(false) << Message;
  }
}

TEST(Component, LoadAndRun_SimpleBinary) {
  Configure Conf;
  Conf.addProposal(WasmEdge::Proposal::Component);
  VM::VM VM(Conf);

  std::vector<uint8_t> Vec = {
      0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00, 0x01, 0x33, 0x00, 0x61,
      0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7e,
      0x01, 0x7e, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x64, 0x75,
      0x70, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x00,
      0x7c, 0x0b, 0x00, 0x09, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x02, 0x01,
      0x4d, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x07, 0x08, 0x01, 0x40, 0x01,
      0x01, 0x61, 0x78, 0x00, 0x78, 0x06, 0x09, 0x01, 0x00, 0x00, 0x01, 0x00,
      0x03, 0x64, 0x75, 0x70, 0x08, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x0b, 0x0a, 0x01, 0x00, 0x04, 0x6d, 0x64, 0x75, 0x70, 0x01, 0x00, 0x00,
      0x00, 0x28, 0x0e, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74,
      0x2d, 0x6e, 0x61, 0x6d, 0x65, 0x01, 0x06, 0x00, 0x11, 0x01, 0x00, 0x01,
      0x4d, 0x01, 0x06, 0x00, 0x12, 0x01, 0x00, 0x01, 0x6d, 0x01, 0x07, 0x01,
      0x01, 0x00, 0x03, 0x72, 0x75, 0x6e,
  };
  assertOk(VM.loadWasm(Vec), "failed to load component binary");
  // TODO: Fix this for the validator.
  /*
  assertOk(VM.validate(), "failed to validate");
  assertOk(VM.instantiate(), "failed to instantiate");

  uint64_t V = 100;
  auto Res = VM.execute("mdup", {ValInterface(ValVariant(V))},
                        {ValType(TypeCode::I64)});
  assertOk(Res, "failed to execute");
  std::vector<std::pair<ValInterface, ValType>> Result = *Res;
  auto Ret = std::get<ValVariant>(Result[0].first).get<uint64_t>();
  EXPECT_EQ(Ret, 200);
  */
}

TEST(Component, Load_HttpBinary) {
  Configure Conf;
  Conf.addProposal(WasmEdge::Proposal::Component);
  VM::VM VM(Conf);

  std::vector<uint8_t> Vec = {
      0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00, 0x01, 0x81, 0x02, 0x00,
      0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x09, 0x01, 0x60, 0x04,
      0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x05, 0x03,
      0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x08, 0x0b, 0x07,
      0x11, 0x02, 0x03, 0x6d, 0x65, 0x6d, 0x02, 0x00, 0x07, 0x72, 0x65, 0x61,
      0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x00, 0x0a, 0x6c, 0x01, 0x6a, 0x01, 0x01,
      0x7f, 0x20, 0x00, 0x04, 0x40, 0x20, 0x01, 0x20, 0x03, 0x4b, 0x04, 0x40,
      0x20, 0x00, 0x0f, 0x0b, 0x0b, 0x23, 0x00, 0x20, 0x02, 0x41, 0x7f, 0x6a,
      0x6a, 0x20, 0x02, 0x41, 0x7f, 0x6a, 0x41, 0x7f, 0x73, 0x71, 0x24, 0x00,
      0x23, 0x00, 0x21, 0x04, 0x23, 0x00, 0x20, 0x03, 0x6a, 0x24, 0x00, 0x03,
      0x40, 0x3f, 0x00, 0x41, 0x80, 0x80, 0x04, 0x6c, 0x23, 0x00, 0x49, 0x04,
      0x40, 0x41, 0x01, 0x40, 0x00, 0x41, 0x7f, 0x46, 0x04, 0x40, 0x00, 0x0b,
      0x0c, 0x01, 0x0b, 0x0b, 0x20, 0x04, 0x41, 0xde, 0x01, 0x20, 0x03, 0xfc,
      0x0b, 0x00, 0x20, 0x00, 0x04, 0x40, 0x20, 0x04, 0x20, 0x00, 0x20, 0x01,
      0xfc, 0x0a, 0x00, 0x00, 0x0b, 0x20, 0x04, 0x0b, 0x00, 0x5a, 0x04, 0x6e,
      0x61, 0x6d, 0x65, 0x00, 0x05, 0x04, 0x4c, 0x69, 0x62, 0x63, 0x01, 0x0a,
      0x01, 0x00, 0x07, 0x72, 0x65, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x02, 0x2c,
      0x01, 0x00, 0x05, 0x00, 0x07, 0x6f, 0x6c, 0x64, 0x5f, 0x70, 0x74, 0x72,
      0x01, 0x08, 0x6f, 0x6c, 0x64, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x02, 0x05,
      0x61, 0x6c, 0x69, 0x67, 0x6e, 0x03, 0x08, 0x6e, 0x65, 0x77, 0x5f, 0x73,
      0x69, 0x7a, 0x65, 0x04, 0x03, 0x72, 0x65, 0x74, 0x03, 0x09, 0x01, 0x00,
      0x01, 0x02, 0x04, 0x6c, 0x6f, 0x6f, 0x70, 0x07, 0x07, 0x01, 0x00, 0x04,
      0x6c, 0x61, 0x73, 0x74, 0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x07, 0x2f,
      0x01, 0x42, 0x04, 0x01, 0x40, 0x01, 0x03, 0x75, 0x72, 0x69, 0x73, 0x00,
      0x73, 0x04, 0x00, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2d, 0x67, 0x65, 0x74,
      0x01, 0x00, 0x01, 0x40, 0x01, 0x04, 0x74, 0x65, 0x78, 0x74, 0x73, 0x01,
      0x00, 0x04, 0x00, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x01, 0x01, 0x0a,
      0x13, 0x01, 0x00, 0x0e, 0x77, 0x61, 0x73, 0x69, 0x3a, 0x68, 0x74, 0x74,
      0x70, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x05, 0x00, 0x06, 0x21, 0x03, 0x01,
      0x00, 0x00, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2d, 0x67, 0x65, 0x74, 0x00,
      0x02, 0x01, 0x00, 0x03, 0x6d, 0x65, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x07,
      0x72, 0x65, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x08, 0x09, 0x01, 0x01, 0x00,
      0x00, 0x02, 0x03, 0x00, 0x04, 0x00, 0x06, 0x1e, 0x03, 0x01, 0x00, 0x00,
      0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x00, 0x02, 0x01, 0x00, 0x03, 0x6d,
      0x65, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x07, 0x72, 0x65, 0x61, 0x6c, 0x6c,
      0x6f, 0x63, 0x08, 0x09, 0x01, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x04,
      0x02, 0x01, 0x8f, 0x01, 0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x15, 0x03, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x60,
      0x02, 0x7f, 0x7f, 0x02, 0x7f, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x02,
      0x39, 0x04, 0x04, 0x6c, 0x69, 0x62, 0x63, 0x03, 0x6d, 0x65, 0x6d, 0x02,
      0x00, 0x01, 0x04, 0x6c, 0x69, 0x62, 0x63, 0x07, 0x72, 0x65, 0x61, 0x6c,
      0x6c, 0x6f, 0x63, 0x00, 0x00, 0x04, 0x68, 0x74, 0x74, 0x70, 0x08, 0x68,
      0x74, 0x74, 0x70, 0x2d, 0x67, 0x65, 0x74, 0x00, 0x01, 0x04, 0x68, 0x74,
      0x74, 0x70, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x00, 0x02, 0x03, 0x02,
      0x01, 0x02, 0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x03, 0x0a,
      0x0c, 0x01, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0x10, 0x01, 0x10, 0x02,
      0x0b, 0x00, 0x18, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x02, 0x01, 0x4d,
      0x01, 0x0d, 0x02, 0x01, 0x03, 0x67, 0x65, 0x74, 0x02, 0x05, 0x70, 0x72,
      0x69, 0x6e, 0x74, 0x02, 0x27, 0x02, 0x01, 0x02, 0x08, 0x68, 0x74, 0x74,
      0x70, 0x2d, 0x67, 0x65, 0x74, 0x00, 0x01, 0x05, 0x70, 0x72, 0x69, 0x6e,
      0x74, 0x00, 0x03, 0x00, 0x01, 0x02, 0x04, 0x6c, 0x69, 0x62, 0x63, 0x12,
      0x00, 0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x01, 0x07, 0x0a, 0x01, 0x40,
      0x01, 0x03, 0x75, 0x72, 0x69, 0x73, 0x01, 0x00, 0x06, 0x1d, 0x03, 0x00,
      0x00, 0x01, 0x02, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x02, 0x01, 0x00, 0x03,
      0x6d, 0x65, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x07, 0x72, 0x65, 0x61, 0x6c,
      0x6c, 0x6f, 0x63, 0x08, 0x0a, 0x01, 0x00, 0x00, 0x04, 0x02, 0x03, 0x02,
      0x04, 0x05, 0x01, 0x0b, 0x09, 0x01, 0x00, 0x03, 0x72, 0x75, 0x6e, 0x01,
      0x02, 0x00, 0x00, 0x57, 0x0e, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65,
      0x6e, 0x74, 0x2d, 0x6e, 0x61, 0x6d, 0x65, 0x01, 0x14, 0x00, 0x00, 0x02,
      0x01, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2d, 0x67, 0x65, 0x74, 0x03, 0x05,
      0x70, 0x72, 0x69, 0x6e, 0x74, 0x01, 0x0c, 0x00, 0x11, 0x02, 0x00, 0x04,
      0x4c, 0x69, 0x62, 0x63, 0x01, 0x01, 0x4d, 0x01, 0x0f, 0x00, 0x12, 0x02,
      0x00, 0x04, 0x6c, 0x69, 0x62, 0x63, 0x02, 0x04, 0x6d, 0x61, 0x69, 0x6e,
      0x01, 0x07, 0x01, 0x01, 0x02, 0x03, 0x72, 0x75, 0x6e, 0x01, 0x08, 0x05,
      0x01, 0x00, 0x04, 0x68, 0x74, 0x74, 0x70,
  };
  assertOk(VM.loadWasm(Vec), "failed to load component binary");

  // TODO: Fix this for the validator.
  // assertOk(VM.validate(), "failed to validate");
}

} // namespace
